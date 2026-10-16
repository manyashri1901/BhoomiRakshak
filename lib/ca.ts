// lib/ca.ts
//
// BhoomiRakshak Certificate Authority (CA) module.
//
// A real, two-tier X.509 v3 PKI, built with @peculiar/x509 (no hand-rolled
// ASN.1 anywhere in this codebase):
//   - A ROOT CA (self-signed, CA:true, pathLen:1) is the trust anchor.
//     Its private key is generated once by scripts/first-run.ts, written
//     ONLY to keys/root-offline/root-ca-private.pem, and never loaded by
//     this running server again — see ensureIssuingCA() below, which
//     loads the issuing key + both certs, never the root key.
//   - An ISSUING CA (signed by the root, CA:true, pathLen:0) is what this
//     server actually holds and signs with day to day.
//   - Every registered user gets a leaf certificate (CA:false,
//     KeyUsage digitalSignature) signed by the Issuing CA, subject
//     CN=<name>, OU=<role>, with a CRL Distribution Point extension
//     pointing at this server's signed-CRL endpoint.
//
// Revocation is published as a real, CA-signed X.509 CRL (getSignedCRL())
// — see the long comment there for caching and freshness.

import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { webcrypto } from "node:crypto";
// Must be imported before "@peculiar/x509" below: it carries the
// `import "reflect-metadata"` polyfill @peculiar/x509's own tsyringe
// dependency requires at load time, not just before first use — importing
// "@peculiar/x509" first (even transitively) throws immediately.
import { RSA_SIGNING_ALGORITHM, generateRsaKeyPairPem, importPrivateKeyPem } from "./x509Keys.ts";
import * as x509 from "@peculiar/x509";
import { prisma } from "./prisma.ts";
import { canonicalStringify } from "./canonicalize.ts";
import { appendAuditEntry } from "./audit.ts";
import type { Role } from "../generated/prisma/enums.ts";

// ---------------------------------------------------------------------------
// 1. KEY / CERTIFICATE FILE LAYOUT
// ---------------------------------------------------------------------------

// CA_KEYS_DIR lets a caller point this module at a throwaway directory
// instead of the real keys/ (scripts/test-first-run-e2e.ts does this, to
// prove the bootstrap flow works from scratch without touching real key
// material) — must be set before this module is first imported, since
// these paths are resolved once at module load.
const CA_DIR = process.env.CA_KEYS_DIR ? path.resolve(process.env.CA_KEYS_DIR) : path.join(process.cwd(), "keys");
const ROOT_OFFLINE_DIR = path.join(CA_DIR, "root-offline");

// Written ONCE by first-run, read ONLY by first-run (to re-derive the
// issuing cert if it's ever regenerated) and by scripts/export-cert-check.ts
// for the interoperability proof. The running server (ensureIssuingCA()
// below) never opens this path.
const ROOT_PRIVATE_KEY_PATH = path.join(ROOT_OFFLINE_DIR, "root-ca-private.pem");
// The root's CERTIFICATE (public) — this one the server does load, as the
// top of the chain it verifies against.
const ROOT_CERT_PATH = path.join(CA_DIR, "root-ca-cert.pem");
const ISSUING_PRIVATE_KEY_PATH = path.join(CA_DIR, "issuing-ca-private.pem");
const ISSUING_CERT_PATH = path.join(CA_DIR, "issuing-ca-cert.pem");

const ROOT_SUBJECT = "CN=BhoomiRakshak Root CA";
const ISSUING_SUBJECT = "CN=BhoomiRakshak Issuing CA";

const ROOT_VALIDITY_DAYS = 3650; // 10 years
const ISSUING_VALIDITY_DAYS = 1825; // 5 years
const CERT_VALIDITY_DAYS = 365; // 1 year — unchanged from before

const DAY_MS = 24 * 60 * 60 * 1000;

function addDays(date: Date, days: number): Date {
  return new Date(date.getTime() + days * DAY_MS);
}

function decodeBase64Pem(value: string): string {
  return Buffer.from(value, "base64").toString("utf8");
}

// ---------------------------------------------------------------------------
// 2. SERIAL NUMBERS
// ---------------------------------------------------------------------------

/**
 * A random 128-bit serial, hex-encoded (32 characters) — the top bit of
 * the first byte is cleared so the value decodes as a positive ASN.1
 * INTEGER (an odd-length/high-bit-set hex string gets silently padded
 * with a leading zero byte by the DER encoder, which would silently
 * change a 16-byte value into a 17-byte one; clearing the bit up front
 * avoids that entirely rather than relying on it).
 */
function generateSerialNumber(): string {
  const bytes = crypto.randomBytes(16);
  bytes[0] &= 0x7f;
  return bytes.toString("hex");
}

// ---------------------------------------------------------------------------
// 3. CA BOOTSTRAP (scripts/first-run.ts only) AND RUNTIME LOADING
// ---------------------------------------------------------------------------

export interface BootstrapResult {
  rootGenerated: boolean;
  issuingGenerated: boolean;
  // Only the ROOT CERTIFICATE (public) is ever returned for the root tier
  // — deliberately no rootPrivateKeyBase64 field exists anywhere on this
  // type, so there is no code path by which the root private key could
  // ever be logged, printed, or returned to a caller: it is written
  // straight to keys/root-offline/root-ca-private.pem inside this
  // function and nowhere else, full stop. The issuing key DOES get
  // returned (as base64, only when freshly generated) because the
  // deployment story requires an operator to be able to copy it into a
  // secret store — scripts/first-run.ts prints it once, loudly, exactly
  // like the single-tier CA this replaces did for its one key.
  rootCertBase64?: string;
  issuingPrivateKeyBase64?: string;
  issuingCertBase64?: string;
}

/**
 * Generates the root and/or issuing CA if either is missing, writing the
 * root private key ONLY to keys/root-offline/ and discarding it from
 * memory immediately after it signs the issuing certificate — it is never
 * cached at module level the way the issuing key is (see
 * ensureIssuingCA()). Safe to call on every deploy: a no-op for whichever
 * tier already exists on disk or via env vars.
 */
export async function bootstrapCAHierarchy(): Promise<BootstrapResult> {
  const result: BootstrapResult = { rootGenerated: false, issuingGenerated: false };

  const envRootCert = process.env.ROOT_CA_CERT_BASE64;
  const rootCertExists = Boolean(envRootCert) || fs.existsSync(ROOT_CERT_PATH);
  const envIssuing =
    process.env.ISSUING_CA_PRIVATE_KEY_BASE64 && process.env.ISSUING_CA_CERT_BASE64;
  const issuingExists = Boolean(envIssuing) || (fs.existsSync(ISSUING_PRIVATE_KEY_PATH) && fs.existsSync(ISSUING_CERT_PATH));

  if (issuingExists) {
    // Nothing to do — whatever is missing (root cert alone, without a
    // reason to regenerate issuing) isn't this function's job to fix;
    // ensureIssuingCA() will simply fail loudly if the root cert is
    // genuinely absent, which first-run's own checks should have caught.
    return result;
  }

  // Need to generate the issuing CA, which means we need the root's
  // PRIVATE key to sign it — generate the root fresh if it doesn't
  // already have a private key available offline.
  let rootPrivateKey: CryptoKey;
  let rootCert: x509.X509Certificate;

  if (rootCertExists && fs.existsSync(ROOT_PRIVATE_KEY_PATH)) {
    // Root already bootstrapped in a prior run on this machine (unusual —
    // normally root-offline/ has been moved off-box by now — but still
    // supported for local dev convenience).
    rootPrivateKey = await importPrivateKeyPem(fs.readFileSync(ROOT_PRIVATE_KEY_PATH, "utf8"));
    rootCert = new x509.X509Certificate(
      envRootCert ? decodeBase64Pem(envRootCert) : fs.readFileSync(ROOT_CERT_PATH, "utf8"),
    );
  } else if (rootCertExists) {
    // The root certificate is known (e.g. via ROOT_CA_CERT_BASE64) but its
    // private key is not available here — this deployment cannot sign a
    // new issuing CA; it must receive ISSUING_CA_PRIVATE_KEY_BASE64 from
    // wherever the root key actually lives instead.
    throw new Error(
      "Root CA certificate is present but its private key is not available in this environment — " +
        "cannot generate a new Issuing CA here. Set ISSUING_CA_PRIVATE_KEY_BASE64/ISSUING_CA_CERT_BASE64 " +
        "instead, generated wherever the root private key actually lives.",
    );
  } else {
    const generated = await generateRsaKeyPairPem();
    rootPrivateKey = generated.keyPair.privateKey;
    const notBefore = new Date();
    rootCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: generateSerialNumber(),
      name: ROOT_SUBJECT,
      notBefore,
      notAfter: addDays(notBefore, ROOT_VALIDITY_DAYS),
      signingAlgorithm: RSA_SIGNING_ALGORITHM,
      keys: generated.keyPair,
      extensions: [
        new x509.BasicConstraintsExtension(true, 1, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
        await x509.SubjectKeyIdentifierExtension.create(generated.keyPair.publicKey),
      ],
    });

    fs.mkdirSync(ROOT_OFFLINE_DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(ROOT_PRIVATE_KEY_PATH, generated.pem.privateKey, { mode: 0o600 });
    fs.mkdirSync(CA_DIR, { recursive: true });
    fs.writeFileSync(ROOT_CERT_PATH, rootCert.toString("pem"), { mode: 0o644 });

    result.rootGenerated = true;
    result.rootCertBase64 = Buffer.from(rootCert.toString("pem"), "utf8").toString("base64");
  }

  // Generate the issuing CA, signed by the root key above (which only
  // ever exists in this function's local scope — nothing module-level
  // retains it after this function returns).
  const issuingKeys = (await webcrypto.subtle.generateKey(RSA_SIGNING_ALGORITHM, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const issuingNotBefore = new Date();
  const issuingCert = await x509.X509CertificateGenerator.create({
    serialNumber: generateSerialNumber(),
    subject: ISSUING_SUBJECT,
    issuer: rootCert.subject,
    notBefore: issuingNotBefore,
    notAfter: addDays(issuingNotBefore, ISSUING_VALIDITY_DAYS),
    signingAlgorithm: RSA_SIGNING_ALGORITHM,
    publicKey: issuingKeys.publicKey,
    signingKey: rootPrivateKey,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      await x509.SubjectKeyIdentifierExtension.create(issuingKeys.publicKey),
    ],
  });
  const issuingPrivateKeyDer = await webcrypto.subtle.exportKey("pkcs8", issuingKeys.privateKey);
  const issuingPrivateKeyPem = `-----BEGIN PRIVATE KEY-----\n${Buffer.from(issuingPrivateKeyDer)
    .toString("base64")
    .match(/.{1,64}/g)!
    .join("\n")}\n-----END PRIVATE KEY-----\n`;

  fs.mkdirSync(CA_DIR, { recursive: true });
  fs.writeFileSync(ISSUING_PRIVATE_KEY_PATH, issuingPrivateKeyPem, { mode: 0o600 });
  fs.writeFileSync(ISSUING_CERT_PATH, issuingCert.toString("pem"), { mode: 0o644 });

  result.issuingGenerated = true;
  result.issuingPrivateKeyBase64 = Buffer.from(issuingPrivateKeyPem, "utf8").toString("base64");
  result.issuingCertBase64 = Buffer.from(issuingCert.toString("pem"), "utf8").toString("base64");

  return result;
}

interface LoadedIssuingCA {
  issuingPrivateKey: CryptoKey;
  issuingCert: x509.X509Certificate;
  rootCert: x509.X509Certificate;
}

let cachedIssuingCA: LoadedIssuingCA | null = null;

/**
 * Loads what the RUNNING SERVER needs to sign and verify certificates day
 * to day: the Issuing CA's private key and certificate, plus the root
 * CERTIFICATE (public — needed to verify the issuing cert's own chain
 * link, never to sign anything). The root PRIVATE key is never read here;
 * if it's genuinely missing, that's scripts/first-run.ts's problem to
 * have caught, not something this function falls back to generating.
 */
export async function ensureIssuingCA(): Promise<LoadedIssuingCA> {
  if (cachedIssuingCA) return cachedIssuingCA;

  const envIssuingKey = process.env.ISSUING_CA_PRIVATE_KEY_BASE64;
  const envIssuingCert = process.env.ISSUING_CA_CERT_BASE64;
  const envRootCert = process.env.ROOT_CA_CERT_BASE64;

  let issuingPrivateKeyPem: string;
  let issuingCertPem: string;
  let rootCertPem: string;

  if (envIssuingKey && envIssuingCert && envRootCert) {
    issuingPrivateKeyPem = decodeBase64Pem(envIssuingKey);
    issuingCertPem = decodeBase64Pem(envIssuingCert);
    rootCertPem = decodeBase64Pem(envRootCert);
  } else if (
    fs.existsSync(ISSUING_PRIVATE_KEY_PATH) &&
    fs.existsSync(ISSUING_CERT_PATH) &&
    fs.existsSync(ROOT_CERT_PATH)
  ) {
    issuingPrivateKeyPem = fs.readFileSync(ISSUING_PRIVATE_KEY_PATH, "utf8");
    issuingCertPem = fs.readFileSync(ISSUING_CERT_PATH, "utf8");
    rootCertPem = fs.readFileSync(ROOT_CERT_PATH, "utf8");
  } else {
    throw new Error(
      "Issuing CA not found (no env vars, no keys/issuing-ca-*.pem + keys/root-ca-cert.pem on disk) — " +
        "run `npm run first-run` first.",
    );
  }

  cachedIssuingCA = {
    issuingPrivateKey: await importPrivateKeyPem(issuingPrivateKeyPem),
    issuingCert: new x509.X509Certificate(issuingCertPem),
    rootCert: new x509.X509Certificate(rootCertPem),
  };
  return cachedIssuingCA;
}

// ---------------------------------------------------------------------------
// 4. CA PUBLIC IDENTITY (client-side verification bootstrap)
// ---------------------------------------------------------------------------

export interface CAPublicCertificates {
  rootCertPem: string;
  issuingCertPem: string;
  // SHA-256 of the ROOT certificate's DER — the actual trust anchor an
  // operator would publish out-of-band for pinning. Same convention as a
  // leaf certificate's own fingerprint.
  fingerprint: string;
}

export async function getCAPublicCertificates(): Promise<CAPublicCertificates> {
  const { rootCert, issuingCert } = await ensureIssuingCA();
  const digest = await webcrypto.subtle.digest("SHA-256", rootCert.rawData);
  return {
    rootCertPem: rootCert.toString("pem"),
    issuingCertPem: issuingCert.toString("pem"),
    fingerprint: Buffer.from(digest).toString("hex"),
  };
}

// ---------------------------------------------------------------------------
// 5. CERTIFICATE ISSUANCE
// ---------------------------------------------------------------------------

export interface IssueCertificateInput {
  id: string;
  name: string;
  role: Role;
  publicKey: string; // SPKI PEM, generated client-side exactly as before
}

export interface IssuedCertificate {
  id: string;
  serialNumber: string;
  certificatePem: string;
  fingerprint: string;
  issuer: string;
  issuedAt: string;
  expiresAt: string;
}

function pemToDerBuffer(pem: string): ArrayBuffer {
  const base64 = pem.replace(/-----BEGIN [^-]+-----/, "").replace(/-----END [^-]+-----/, "").replace(/\s+/g, "");
  const buf = Buffer.from(base64, "base64");
  // See the identical comment in lib/x509Keys.ts's pemToDer(): a small
  // Buffer.from(string, "base64") is a view into a shared pool, so
  // buf.buffer alone is the wrong (and wrong-sized) ArrayBuffer unless this
  // happens to be the first small Buffer decoded in the process. Slice to
  // this buffer's own range.
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

const API_PUBLIC_URL = process.env.API_PUBLIC_URL ?? "http://localhost:4000";

/**
 * Issues a leaf X.509 certificate for `user`, signed by the Issuing CA:
 * CA:false, KeyUsage digitalSignature, subject CN=<name>,OU=<role>, a CRL
 * Distribution Point pointing at this server's signed-CRL endpoint, and a
 * random 128-bit serial. Persists the full certificatePem — nothing about
 * the certificate's own signature/public key is stored as a separate
 * column, so there is nothing that can drift from what was actually signed.
 */
export async function issueCertificate(user: IssueCertificateInput): Promise<IssuedCertificate> {
  const { issuingPrivateKey, issuingCert } = await ensureIssuingCA();

  const issuedAtDate = new Date();
  const expiresAtDate = addDays(issuedAtDate, CERT_VALIDITY_DAYS);
  const serialNumber = generateSerialNumber();

  const cert = await x509.X509CertificateGenerator.create({
    serialNumber,
    subject: `CN=${user.name},OU=${user.role}`,
    issuer: issuingCert.subject,
    notBefore: issuedAtDate,
    notAfter: expiresAtDate,
    signingAlgorithm: RSA_SIGNING_ALGORITHM,
    publicKey: pemToDerBuffer(user.publicKey),
    signingKey: issuingPrivateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature),
      new x509.CRLDistributionPointsExtension([`${API_PUBLIC_URL}/api/certificates/crl/signed`]),
    ],
  });

  const fingerprint = Buffer.from(
    await webcrypto.subtle.digest("SHA-256", cert.rawData),
  ).toString("hex");
  const certificatePem = cert.toString("pem");

  const record = await prisma.certificate.create({
    data: {
      subjectUserId: user.id,
      role: user.role,
      serialNumber,
      certificatePem,
      fingerprint,
      issuedAt: issuedAtDate,
      expiresAt: expiresAtDate,
    },
  });

  await appendAuditEntry({
    action: "CERTIFICATE_ISSUED",
    actorUserId: user.id,
    entityType: "CERTIFICATE",
    entityId: record.id,
    details: { subjectUserId: user.id, role: user.role, serialNumber, fingerprint },
  });

  return {
    id: record.id,
    serialNumber,
    certificatePem,
    fingerprint,
    issuer: issuingCert.subject,
    issuedAt: issuedAtDate.toISOString(),
    expiresAt: expiresAtDate.toISOString(),
  };
}

// ---------------------------------------------------------------------------
// 6. CERTIFICATE VERIFICATION (full chain: user -> issuing -> root)
// ---------------------------------------------------------------------------

export interface VerifyCertificateResult {
  valid: boolean;
  details: {
    certificateId: string;
    subject: string;
    name: string;
    role: string;
    serialNumber: string;
    issuer: string;
    issuedAt: string;
    expiresAt: string;
    fingerprint: string;
    // Each link verified independently, never short-circuited, so a
    // caller (or a report) can tell exactly which link in the chain broke.
    userSignatureValid: boolean; // user cert signed by the issuing CA
    issuingSignatureValid: boolean; // issuing cert signed by the root CA
    withinValidityWindow: boolean;
    keyUsageValid: boolean; // digitalSignature bit present
    expired: boolean;
    revoked: boolean;
    revokedReason: string | null;
    reason: string | null;
  };
}

export async function verifyCertificateForUser(userId: string): Promise<VerifyCertificateResult | null> {
  const certificate = await prisma.certificate.findUnique({ where: { subjectUserId: userId } });
  if (!certificate) return null;
  return verifyCertificate(certificate.id);
}

export async function verifyCertificate(certificateId: string): Promise<VerifyCertificateResult> {
  const { issuingCert, rootCert } = await ensureIssuingCA();

  const cert = await prisma.certificate.findUnique({
    where: { id: certificateId },
    include: { subject: { select: { name: true } } },
  });
  if (!cert) {
    throw new Error(`Certificate not found: ${certificateId}`);
  }

  const parsed = new x509.X509Certificate(cert.certificatePem);

  // signatureOnly: true is required — @peculiar/x509's X509Certificate
  // .verify() otherwise ALSO folds the certificate's own notBefore/
  // notAfter window into its result by default, silently returning false
  // for a genuinely, correctly signed but merely-expired certificate. That
  // would make a signature check indistinguishable from an actual forgery
  // and corrupt `reason` below ("forged or tampered" would be reported for
  // a cert that's simply expired) — `expired`/`withinValidityWindow` below
  // already cover the time window independently, which is the whole point
  // of reporting these as separate fields.
  const userSignatureValid = await parsed.verify({ publicKey: issuingCert.publicKey, signatureOnly: true });
  const issuingSignatureValid = await issuingCert.verify({ publicKey: rootCert.publicKey, signatureOnly: true });

  const now = new Date();
  const withinValidityWindow = now >= parsed.notBefore && now <= parsed.notAfter;
  const expired = now > parsed.notAfter;

  const keyUsage = parsed.getExtension(x509.KeyUsagesExtension);
  const keyUsageValid = Boolean(keyUsage && keyUsage.usages & x509.KeyUsageFlags.digitalSignature);

  const revoked = cert.revoked;

  const valid =
    userSignatureValid && issuingSignatureValid && withinValidityWindow && keyUsageValid && !revoked;

  let reason: string | null = null;
  if (!valid) {
    if (!userSignatureValid) reason = "Certificate signature does not match the Issuing CA's public key (forged or tampered).";
    else if (!issuingSignatureValid) reason = "The Issuing CA's own certificate does not verify against the Root CA — chain is broken.";
    else if (revoked) reason = `Certificate was revoked${cert.revokedReason ? `: ${cert.revokedReason}` : "."}`;
    else if (expired) reason = `Certificate expired on ${parsed.notAfter.toISOString()}.`;
    else if (!withinValidityWindow) reason = `Certificate is not yet valid (notBefore ${parsed.notBefore.toISOString()}).`;
    else if (!keyUsageValid) reason = "Certificate does not carry the digitalSignature key usage.";
  }

  return {
    valid,
    details: {
      certificateId: cert.id,
      subject: cert.subjectUserId,
      name: cert.subject.name,
      role: cert.role,
      serialNumber: cert.serialNumber,
      issuer: parsed.issuer,
      issuedAt: cert.issuedAt.toISOString(),
      expiresAt: cert.expiresAt.toISOString(),
      fingerprint: cert.fingerprint,
      userSignatureValid,
      issuingSignatureValid,
      withinValidityWindow,
      keyUsageValid,
      expired,
      revoked,
      revokedReason: cert.revokedReason,
      reason,
    },
  };
}

/**
 * Extracts the SPKI PEM public key from a stored certificate's PEM — the
 * one place routes/transactions.ts should get an actor's public key from
 * for a signature check, instead of trusting a separately-stored column
 * that could in principle drift from what the certificate actually says.
 */
export function publicKeyPemFromCertificatePem(certificatePem: string): string {
  return new x509.X509Certificate(certificatePem).publicKey.toString("pem");
}

// ---------------------------------------------------------------------------
// 7. CERTIFICATE REVOCATION (CRL)
// ---------------------------------------------------------------------------

export interface RevokeCertificateInput {
  certificateId: string;
  revokedByUserId: string;
  reason: string;
}

export interface RevokedCertificateSummary {
  certificateId: string;
  serialNumber: string;
  subjectUserId: string;
  subjectName: string;
  role: string;
  fingerprint: string;
  revokedAt: string;
  revokedReason: string | null;
  revokedByUserId: string | null;
}

export async function revokeCertificate(input: RevokeCertificateInput): Promise<RevokedCertificateSummary> {
  const cert = await prisma.certificate.findUnique({
    where: { id: input.certificateId },
    include: { subject: { select: { name: true } } },
  });
  if (!cert) {
    throw new Error(`Certificate not found: ${input.certificateId}`);
  }
  if (cert.revoked) {
    throw new Error("Certificate is already revoked");
  }

  const revokedAt = new Date();
  const updated = await prisma.certificate.update({
    where: { id: input.certificateId },
    data: { revoked: true, revokedAt, revokedReason: input.reason, revokedByUserId: input.revokedByUserId },
  });

  invalidateCrlCache();

  await appendAuditEntry({
    action: "CERTIFICATE_REVOKED",
    actorUserId: input.revokedByUserId,
    entityType: "CERTIFICATE",
    entityId: updated.id,
    details: { subjectUserId: updated.subjectUserId, reason: input.reason },
  });

  return {
    certificateId: updated.id,
    subjectUserId: updated.subjectUserId,
    subjectName: cert.subject.name,
    role: updated.role,
    fingerprint: updated.fingerprint,
    revokedAt: revokedAt.toISOString(),
    revokedReason: updated.revokedReason,
    revokedByUserId: updated.revokedByUserId,
  };
}

/**
 * The plain, unsigned revoked-certificate list — feeds the Admin UI's CRL
 * table only. Left exactly as it behaved before this rework.
 */
export async function getCRL(): Promise<RevokedCertificateSummary[]> {
  const revoked = await prisma.certificate.findMany({
    where: { revoked: true },
    include: { subject: { select: { name: true } } },
    orderBy: { revokedAt: "desc" },
  });

  return revoked.map((cert) => ({
    certificateId: cert.id,
    serialNumber: cert.serialNumber,
    subjectUserId: cert.subjectUserId,
    subjectName: cert.subject.name,
    role: cert.role,
    fingerprint: cert.fingerprint,
    revokedAt: (cert.revokedAt ?? cert.issuedAt).toISOString(),
    revokedReason: cert.revokedReason,
    revokedByUserId: cert.revokedByUserId,
  }));
}

const CRL_VALIDITY_MS = 60 * 60 * 1000; // 1 hour — the CRL's own thisUpdate/nextUpdate window
const CRL_CACHE_MS = 3 * 60 * 1000; // regenerate at most every 3 minutes

export interface SignedCRL {
  pem: string;
  thisUpdate: string;
  nextUpdate: string;
}

let cachedCrl: { crl: SignedCRL; generatedAt: number } | null = null;

function invalidateCrlCache(): void {
  cachedCrl = null;
}

/**
 * A real, CA-signed X.509 CRL (X509CrlGenerator) listing every revoked
 * certificate's serial, thisUpdate=now, nextUpdate=+1h. Regenerating and
 * re-signing a CRL is cheap but not free, and this endpoint is hit by
 * every client-side verification — so the generated CRL is cached in
 * memory for a few minutes (CRL_CACHE_MS) independent of its own
 * thisUpdate/nextUpdate window (which governs how long a CLIENT should
 * trust a cached copy, a different and longer concern). revokeCertificate()
 * explicitly invalidates this cache, so a fresh revocation is never
 * masked by a stale in-memory CRL for the full 3 minutes.
 */
export async function getSignedCRL(): Promise<SignedCRL> {
  if (cachedCrl && Date.now() - cachedCrl.generatedAt < CRL_CACHE_MS) {
    return cachedCrl.crl;
  }

  const { issuingPrivateKey, issuingCert } = await ensureIssuingCA();
  const revoked = await getCRL();

  const thisUpdate = new Date();
  const nextUpdate = new Date(thisUpdate.getTime() + CRL_VALIDITY_MS);

  const crl = await x509.X509CrlGenerator.create({
    issuer: issuingCert.subject,
    thisUpdate,
    nextUpdate,
    signingAlgorithm: RSA_SIGNING_ALGORITHM,
    signingKey: issuingPrivateKey,
    entries: revoked.map((r) => ({
      serialNumber: r.serialNumber,
      revocationDate: new Date(r.revokedAt),
      reason: x509.X509CrlReason.unspecified,
    })),
  });

  const signed: SignedCRL = {
    pem: crl.toString("pem"),
    thisUpdate: thisUpdate.toISOString(),
    nextUpdate: nextUpdate.toISOString(),
  };
  cachedCrl = { crl: signed, generatedAt: Date.now() };
  return signed;
}

// ---------------------------------------------------------------------------
// 8. ADMIN BOOTSTRAP KEY PAIR GENERATION
// ---------------------------------------------------------------------------

/**
 * Generates a fresh RSA-2048 key pair (Node's own crypto, PEM-encoded —
 * this is a one-off throwaway key for the ADMIN bootstrap account, whose
 * private key is discarded immediately, never wrapped or stored; it has
 * nothing to do with @peculiar/x509 or the CA's own keys). ONLY used by
 * scripts/create-first-admin.ts (and scripts/test-ca.ts for
 * demonstration) — every normal user generates their own key pair in the
 * browser instead (frontend/src/lib/clientCrypto.ts).
 */
export function generateUserKeyPair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

// ---------------------------------------------------------------------------
// 9. REGISTRATION PROOF OF POSSESSION (client-side keys)
// ---------------------------------------------------------------------------
//
// Unchanged by the X.509 rework — this has nothing to do with the
// certificate's own container format. It proves the browser that
// submitted `publicKey` at registration also holds the matching private
// key, BEFORE any certificate exists for it to be embedded in. See the
// original (pre-rework) comment here for the full rationale; preserved
// verbatim below.
//
// issueCertificate() trusts whatever public key it is handed. Without this
// check, nothing stops a registration request from submitting a public key
// it doesn't actually control the matching private key for — the CA would
// then issue a certificate binding an identity to a key the registrant can
// never sign with, or worse, to a key someone else controls.
//
// Since the key pair is generated in the browser (frontend/src/lib/
// clientCrypto.ts), proof of possession can't be a server-issued
// challenge-response round trip without an extra request — instead the
// browser itself builds a canonical string of {email, fingerprint,
// timestamp}, signs it with the private key it just generated (before
// that key is ever wrapped/discarded), and sends {publicKey, signature,
// timestamp} in the same registration request. The server re-derives the
// exact same canonical string from its own view of the request (never
// trusting a client-supplied payload) and checks:
//  (a) timestamp is a valid ISO date within ±5 minutes of server time —
//      bounds how long a captured signature could be replayed as a fresh
//      registration attempt, without requiring state (a stored nonce) for
//      something that only ever needs to happen once per registration.
//  (b) the signature verifies against the submitted public key.
// Both must hold for the proof to be accepted.

const REGISTRATION_PROOF_WINDOW_MS = 5 * 60 * 1000;

export interface RegistrationProofInput {
  email: string;
  publicKey: string;
  timestamp: string; // ISO 8601, as sent by the client
  signature: string; // base64
}

export interface RegistrationProofResult {
  valid: boolean;
  reason: string | null;
}

export function verifyRegistrationProof(input: RegistrationProofInput): RegistrationProofResult {
  const timestampMs = Date.parse(input.timestamp);
  if (Number.isNaN(timestampMs)) {
    return { valid: false, reason: "timestamp is not a valid ISO 8601 date" };
  }
  const skewMs = Math.abs(Date.now() - timestampMs);
  if (skewMs > REGISTRATION_PROOF_WINDOW_MS) {
    return { valid: false, reason: "timestamp is outside the 5-minute acceptance window" };
  }

  let fingerprint: string;
  try {
    fingerprint = crypto.createHash("sha256").update(input.publicKey, "utf8").digest("hex");
  } catch {
    return { valid: false, reason: "publicKey is not a valid PEM key" };
  }

  const canonical = canonicalStringify({ email: input.email, fingerprint, timestamp: input.timestamp });
  const canonicalBuffer = Buffer.from(canonical, "utf8");

  try {
    const signatureValid = crypto.verify(
      "RSA-SHA256",
      canonicalBuffer,
      input.publicKey,
      Buffer.from(input.signature, "base64"),
    );
    if (!signatureValid) {
      return { valid: false, reason: "signature does not match the submitted public key" };
    }
    return { valid: true, reason: null };
  } catch {
    return { valid: false, reason: "malformed public key or signature" };
  }
}
