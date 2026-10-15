// lib/ca.ts
//
// BhoomiRakshak Certificate Authority (CA) module.
//
// This implements a minimal, self-hosted PKI:
//   - A single root CA key pair (RSA-2048) acts as the trust anchor.
//   - Every registered user (Landowner / Village Officer / Registrar) gets
//     their own RSA-2048 key pair.
//   - The CA "issues" a certificate by signing a canonical JSON payload that
//     binds a user's identity (id, name, role) to their public key.
//   - Anyone holding the CA's public key can later verify that a
//     certificate was really issued by this CA and has not been tampered
//     with, without needing to trust the database.
//
// All crypto here uses Node's built-in `crypto` module (no external
// dependencies) with RSA + SHA-256, matching the schema's design.

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { prisma } from "./prisma.ts";
import { canonicalStringify } from "./canonicalize.ts";
import { appendAuditEntry } from "./audit.ts";
import type { Role } from "../generated/prisma/enums.ts";

// ---------------------------------------------------------------------------
// 1. ROOT CA KEY PAIR
// ---------------------------------------------------------------------------

const CA_DIR = path.join(process.cwd(), "keys");
const CA_PRIVATE_KEY_PATH = path.join(CA_DIR, "ca-private.pem");
const CA_PUBLIC_KEY_PATH = path.join(CA_DIR, "ca-public.pem");

const CA_ISSUER_NAME = "BhoomiRakshak Root CA";

// Certificates are valid for one year from issuance. This bounds how long a
// compromised or orphaned key pair stays trusted even if it's never
// explicitly revoked — the other half of revocation (see
// revokeCertificate/CRL below), not a replacement for it.
const CERT_VALIDITY_DAYS = 365;

interface KeyPairPem {
  publicKey: string;
  privateKey: string;
}

// Module-level cache so we only touch the filesystem once per process,
// even if ensureRootCA() is called on every request.
let cachedRootCA: KeyPairPem | null = null;

/**
 * Generates a fresh RSA-2048 key pair, PEM-encoded.
 *
 * - modulusLength: 2048  -> the RSA key size in bits. 2048 is the current
 *   practical minimum for RSA (matches the assignment brief); 3072/4096
 *   would be stronger but slower to sign/verify.
 * - publicKeyEncoding:  SPKI  (SubjectPublicKeyInfo) — the standard X.509
 *   container format for public keys.
 * - privateKeyEncoding: PKCS#8 — the standard container format for
 *   private keys (algorithm-agnostic, unlike the older PKCS#1).
 * - Both are exported as PEM (base64 text wrapped with BEGIN/END headers)
 *   so they can be stored as plain text files / DB text columns.
 */
function generateRsaKeyPair(): KeyPairPem {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

function decodeBase64Pem(value: string): string {
  return Buffer.from(value, "base64").toString("utf8");
}

/**
 * Loads the root CA key pair — from environment variables first, falling
 * back to disk (generating it on first run) only if those aren't set.
 *
 * This is the CA's own identity: every certificate issued by
 * issueCertificate() is signed with `privateKey`, and every verification in
 * verifyCertificate() checks against `publicKey`. Losing ca-private.pem
 * means losing the ability to issue new trusted certificates; leaking it
 * means an attacker could forge certificates, so keys/ must never be
 * committed to git (see .gitignore).
 *
 * CA_PRIVATE_KEY_BASE64 / CA_PUBLIC_KEY_BASE64 (base64 of the PEM text, to
 * sidestep every platform's own quirks around multi-line env var values)
 * exist for Render and similar hosts, whose disk is ephemeral — a key
 * generated to keys/ on one deploy would vanish on the next, invalidating
 * every certificate issued under it. Store these as the platform's
 * *secret* env vars, never plain ones, and never log their values (see
 * scripts/first-run.ts, the only place that ever prints them, once, for
 * you to copy into that secret store). Local development has no such
 * constraint, so it's untouched: no env vars set, keys/ persists on disk
 * exactly as before.
 */
export function ensureRootCA(): KeyPairPem {
  if (cachedRootCA) return cachedRootCA;

  const envPrivateKey = process.env.CA_PRIVATE_KEY_BASE64;
  const envPublicKey = process.env.CA_PUBLIC_KEY_BASE64;
  if (envPrivateKey && envPublicKey) {
    cachedRootCA = {
      privateKey: decodeBase64Pem(envPrivateKey),
      publicKey: decodeBase64Pem(envPublicKey),
    };
    return cachedRootCA;
  }

  const alreadyExists =
    fs.existsSync(CA_PRIVATE_KEY_PATH) && fs.existsSync(CA_PUBLIC_KEY_PATH);

  if (alreadyExists) {
    cachedRootCA = {
      privateKey: fs.readFileSync(CA_PRIVATE_KEY_PATH, "utf8"),
      publicKey: fs.readFileSync(CA_PUBLIC_KEY_PATH, "utf8"),
    };
    return cachedRootCA;
  }

  const keyPair = generateRsaKeyPair();

  fs.mkdirSync(CA_DIR, { recursive: true });
  // mode 0o600: owner read/write only (POSIX; a no-op on Windows, but
  // correct and worth stating in a viva as the intended production posture).
  fs.writeFileSync(CA_PRIVATE_KEY_PATH, keyPair.privateKey, { mode: 0o600 });
  fs.writeFileSync(CA_PUBLIC_KEY_PATH, keyPair.publicKey, { mode: 0o644 });

  cachedRootCA = keyPair;
  return cachedRootCA;
}

interface CertificatePayload {
  subject: string;
  name: string;
  role: string;
  publicKey: string;
  issuer: string;
  issuedAt: string;
  expiresAt: string;
}

function buildCertificatePayload(
  user: { id: string; name: string; role: string; publicKey: string },
  issuedAt: string,
  expiresAt: string,
): CertificatePayload {
  return {
    subject: user.id,
    name: user.name,
    role: user.role,
    publicKey: user.publicKey,
    issuer: CA_ISSUER_NAME,
    issuedAt,
    expiresAt,
  };
}

// ---------------------------------------------------------------------------
// 2. CERTIFICATE ISSUANCE
// ---------------------------------------------------------------------------

export interface IssueCertificateInput {
  id: string;
  name: string;
  role: Role;
  publicKey: string;
}

export interface IssuedCertificate {
  id: string;
  subject: string;
  name: string;
  role: string;
  publicKey: string;
  issuer: string;
  issuedAt: string;
  expiresAt: string;
  signature: string;
  fingerprint: string;
  payloadHash: string;
}

/**
 * Issues a signed certificate binding `user.publicKey` to their identity.
 *
 * Steps:
 *  a) Build the certificate payload (what we are vouching for).
 *  b) Canonicalize it and take its SHA-256 digest — this digest is the
 *     fixed-size "fingerprint of the claim" that RSA signing actually
 *     operates on. We compute it explicitly here for transparency/logging;
 *     `crypto.sign("RSA-SHA256", ...)` performs this same SHA-256 hashing
 *     internally before applying the RSA private-key operation (PKCS#1 v1.5
 *     padding), so the two are the same digest.
 *  c) Sign the canonical payload with the CA's RSA private key using
 *     RSA-SHA256. Only someone holding the CA private key could have
 *     produced this signature; anyone with the CA public key can check it.
 *  d) Compute the fingerprint: SHA-256 of the user's public key alone (not
 *     the whole payload). This is a stable, short identifier for "this
 *     exact public key" independent of who it belongs to or when it was
 *     issued — the same convention browsers use for TLS cert fingerprints.
 *  e) Persist the Certificate row via Prisma.
 *  f) Return the full certificate object (including the raw payload hash,
 *     which is not stored in the DB but useful for debugging/viva).
 */
export async function issueCertificate(
  user: IssueCertificateInput,
): Promise<IssuedCertificate> {
  const { privateKey } = ensureRootCA();

  const issuedAtDate = new Date();
  const expiresAtDate = new Date(issuedAtDate);
  expiresAtDate.setUTCDate(expiresAtDate.getUTCDate() + CERT_VALIDITY_DAYS);

  const issuedAt = issuedAtDate.toISOString();
  const expiresAt = expiresAtDate.toISOString();
  const payload = buildCertificatePayload(user, issuedAt, expiresAt);
  const canonicalPayload = canonicalStringify(payload);
  const payloadBuffer = Buffer.from(canonicalPayload, "utf8");

  // (b) Explicit SHA-256 digest of the canonical payload.
  const payloadHash = crypto
    .createHash("sha256")
    .update(payloadBuffer)
    .digest("hex");

  // (c) RSA-SHA256 signature over the canonical payload, using the CA's
  // private key. Stored as base64 text since Signature/Certificate columns
  // are TEXT, not BYTEA.
  const signature = crypto
    .sign("RSA-SHA256", payloadBuffer, privateKey)
    .toString("base64");

  // (d) Fingerprint = SHA-256 of the public key PEM alone.
  const fingerprint = crypto
    .createHash("sha256")
    .update(user.publicKey, "utf8")
    .digest("hex");

  // (e) Persist.
  const record = await prisma.certificate.create({
    data: {
      subjectUserId: user.id,
      role: user.role,
      publicKey: user.publicKey,
      issuer: CA_ISSUER_NAME,
      issuedAt: issuedAtDate,
      expiresAt: expiresAtDate,
      signature,
      fingerprint,
    },
  });

  await appendAuditEntry({
    action: "CERTIFICATE_ISSUED",
    actorUserId: user.id,
    entityType: "CERTIFICATE",
    entityId: record.id,
    details: { subjectUserId: user.id, role: user.role, fingerprint },
  });

  // (f) Return the full certificate, including the payload hash for
  // reference (not persisted as its own column — recomputed on demand by
  // verifyCertificate()).
  return {
    id: record.id,
    subject: user.id,
    name: user.name,
    role: user.role,
    publicKey: user.publicKey,
    issuer: CA_ISSUER_NAME,
    issuedAt,
    expiresAt,
    signature,
    fingerprint,
    payloadHash,
  };
}

// ---------------------------------------------------------------------------
// 3. CERTIFICATE VERIFICATION
// ---------------------------------------------------------------------------

export interface VerifyCertificateResult {
  valid: boolean;
  details: {
    certificateId: string;
    subject: string;
    name: string;
    role: string;
    issuer: string;
    issuedAt: string;
    expiresAt: string;
    fingerprint: string;
    fingerprintMatches: boolean;
    payloadHash: string;
    signatureValid: boolean;
    expired: boolean;
    revoked: boolean;
    revokedReason: string | null;
    // Set only when `valid` is false — the single concrete reason a
    // verify-path caller should surface to the user/report, rather than
    // making them infer it from the boolean flags above.
    reason: string | null;
  };
}

/**
 * Looks up a user's certificate by their user id and verifies it live.
 * Returns null if the user has no certificate at all (should only happen
 * for a user row created outside the normal registration flow).
 *
 * This is the one entry point every signing/approval verify path should
 * use to answer "is this actor's certificate currently trustworthy?" —
 * centralizing the lookup+verify pair so every call site checks expiry and
 * revocation the same way lib/ca.ts itself does, rather than re-deriving
 * that logic (or forgetting a piece of it) at each call site.
 */
export async function verifyCertificateForUser(
  userId: string,
): Promise<VerifyCertificateResult | null> {
  const certificate = await prisma.certificate.findUnique({
    where: { subjectUserId: userId },
  });
  if (!certificate) return null;
  return verifyCertificate(certificate.id);
}

/**
 * Verifies a previously issued certificate.
 *
 * Steps:
 *  a) Load the certificate (and its subject User, for `name`) from the DB.
 *  b) Rebuild the exact canonical payload that was signed at issuance time
 *     — same field set, same key order, same ISO timestamp string.
 *  c) Use crypto.verify with the CA's public key to check the stored
 *     signature against that rebuilt payload. This is the core trust
 *     check: it succeeds only if (1) the payload has not changed since
 *     issuance and (2) the signature was produced by the CA's private key.
 *  d) Also recompute the public-key fingerprint as a sanity check that the
 *     stored publicKey/fingerprint pair is internally consistent.
 */
export async function verifyCertificate(
  certificateId: string,
): Promise<VerifyCertificateResult> {
  const { publicKey: caPublicKey } = ensureRootCA();

  // (a) Fetch certificate + subject. select, not include: true — only the
  // subject's name is ever used below; the full User row carries
  // passwordHash and wrapped key material, neither of which this function
  // (or its callers, some of which return its result to clients) should
  // ever pull into memory.
  const cert = await prisma.certificate.findUnique({
    where: { id: certificateId },
    include: { subject: { select: { name: true } } },
  });

  if (!cert) {
    throw new Error(`Certificate not found: ${certificateId}`);
  }

  // (b) Rebuild the canonical payload exactly as issueCertificate() built it.
  const payload = buildCertificatePayload(
    {
      id: cert.subjectUserId,
      name: cert.subject.name,
      role: cert.role,
      publicKey: cert.publicKey,
    },
    cert.issuedAt.toISOString(),
    cert.expiresAt.toISOString(),
  );
  const canonicalPayload = canonicalStringify(payload);
  const payloadBuffer = Buffer.from(canonicalPayload, "utf8");

  const payloadHash = crypto
    .createHash("sha256")
    .update(payloadBuffer)
    .digest("hex");

  // (c) Verify the RSA-SHA256 signature against the CA's public key.
  const signatureValid = crypto.verify(
    "RSA-SHA256",
    payloadBuffer,
    caPublicKey,
    Buffer.from(cert.signature, "base64"),
  );

  // (d) Recompute the fingerprint from the stored public key and compare.
  const recomputedFingerprint = crypto
    .createHash("sha256")
    .update(cert.publicKey, "utf8")
    .digest("hex");
  const fingerprintMatches = recomputedFingerprint === cert.fingerprint;

  // (e) Validity window + revocation — checked independently of the
  // signature itself: a certificate can be cryptographically genuine and
  // still untrusted because it expired or was revoked after issuance.
  const now = new Date();
  const expired = now > cert.expiresAt;
  const revoked = cert.revoked;

  const valid = signatureValid && fingerprintMatches && !expired && !revoked;

  let reason: string | null = null;
  if (!valid) {
    if (!signatureValid) reason = "Certificate signature does not match the CA's public key (forged or tampered).";
    else if (!fingerprintMatches) reason = "Stored fingerprint does not match the certificate's public key.";
    else if (revoked) reason = `Certificate was revoked${cert.revokedReason ? `: ${cert.revokedReason}` : "."}`;
    else if (expired) reason = `Certificate expired on ${cert.expiresAt.toISOString()}.`;
  }

  return {
    valid,
    details: {
      certificateId: cert.id,
      subject: cert.subjectUserId,
      name: cert.subject.name,
      role: cert.role,
      issuer: cert.issuer,
      issuedAt: cert.issuedAt.toISOString(),
      expiresAt: cert.expiresAt.toISOString(),
      fingerprint: cert.fingerprint,
      fingerprintMatches,
      payloadHash,
      signatureValid,
      expired,
      revoked,
      revokedReason: cert.revokedReason,
      reason,
    },
  };
}

// ---------------------------------------------------------------------------
// 3b. CERTIFICATE REVOCATION (CRL)
// ---------------------------------------------------------------------------
//
// Revocation is the half of PKI trust that an expiry date alone can't cover:
// a key compromised today must stop being trusted today, not up to a year
// from now. Revoking never touches the certificate's signature or deletes
// the row — it's a separate, additive fact ("the CA no longer vouches for
// this") that every verify path (verifyCertificate above, and every
// signature-chain check that calls it) must check independently of the
// signature's own cryptographic validity.

export interface RevokeCertificateInput {
  certificateId: string;
  revokedByUserId: string;
  reason: string;
}

export interface RevokedCertificateSummary {
  certificateId: string;
  subjectUserId: string;
  subjectName: string;
  role: string;
  fingerprint: string;
  revokedAt: string;
  revokedReason: string | null;
  revokedByUserId: string | null;
}

export async function revokeCertificate(
  input: RevokeCertificateInput,
): Promise<RevokedCertificateSummary> {
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
    data: {
      revoked: true,
      revokedAt,
      revokedReason: input.reason,
      revokedByUserId: input.revokedByUserId,
    },
  });

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

// ---------------------------------------------------------------------------
// 3c. CA PUBLIC IDENTITY + SIGNED CRL (client-side certificate verification)
// ---------------------------------------------------------------------------
//
// The two functions below exist so the BROWSER can independently verify a
// certificate's authenticity and revocation status itself — see
// frontend/src/lib/certificateVerify.ts — rather than trusting a verdict
// computed only by this server. getCAPublicCertificate() publishes what the
// browser needs to bootstrap that trust (the CA's own public key); getSignedCRL()
// publishes a CA-signed, freshness-bounded revocation list the browser can
// check a certificate's serial against without a live per-certificate query.

export interface CAPublicCertificate {
  issuer: string;
  publicKey: string;
  // SHA-256 of the CA public key PEM — same convention as a certificate's
  // own fingerprint. Displayed on the Certificate Lookup page so a user
  // has *something* concrete to compare against an out-of-band published
  // value, which is the actual trust-bootstrap mechanism in a real
  // deployment (see the comment on the /ca route for why fetching it from
  // this same server doesn't by itself establish trust).
  fingerprint: string;
}

export function getCAPublicCertificate(): CAPublicCertificate {
  const { publicKey } = ensureRootCA();
  const fingerprint = crypto.createHash("sha256").update(publicKey, "utf8").digest("hex");
  return { issuer: CA_ISSUER_NAME, publicKey, fingerprint };
}

// The CRL is only ever valid for this long after it's issued — the
// browser's own verify helper treats a CRL older than this as untrustworthy
// (reported under its "CRL freshness" check) regardless of whether its
// signature still verifies, since a stale-but-genuinely-signed CRL could be
// replayed to hide a revocation that happened after it was issued.
const CRL_VALIDITY_MS = 60 * 60 * 1000; // 1 hour

export interface SignedCRL {
  type: "CRL";
  issuer: string;
  thisUpdate: string;
  nextUpdate: string;
  revokedSerials: string[];
  signature: string;
}

interface CRLPayload {
  type: "CRL";
  issuer: string;
  thisUpdate: string;
  nextUpdate: string;
  revokedSerials: string[];
}

/**
 * A CA-signed, freshness-bounded Certificate Revocation List — distinct
 * from getCRL() below (which returns the same revoked set as a plain,
 * unsigned list for the Admin UI's CRL table and is left untouched).
 *
 * Domain separation: this payload carries an explicit `type: "CRL"` field
 * precisely so a CRL signature can never be confused with a certificate
 * signature. Certificates (buildCertificatePayload, above) do NOT get an
 * equivalent tag — adding one would change the exact bytes
 * verifyCertificate() reconstructs and checks the stored signature
 * against, which would invalidate every certificate already issued before
 * this change (their signature was computed over the untagged shape and
 * can never be made to match a differently-shaped rebuild). In practice
 * this is not a live confusion risk even without the tag: a certificate
 * payload's key set ({subject,name,role,publicKey,issuer,issuedAt,
 * expiresAt}) and this CRL payload's key set ({type,issuer,thisUpdate,
 * nextUpdate,revokedSerials}) are completely disjoint, so
 * canonicalStringify() can never produce identical bytes for one as for
 * the other regardless of field values — the `type` tag here is
 * defense-in-depth for this payload and any future one, not a fix for an
 * exploitable gap in the certificate payload today.
 */
export function getSignedCRL(): Promise<SignedCRL> {
  return getCRL().then((revoked) => {
    const { privateKey } = ensureRootCA();
    const thisUpdate = new Date();
    const nextUpdate = new Date(thisUpdate.getTime() + CRL_VALIDITY_MS);

    const payload: CRLPayload = {
      type: "CRL",
      issuer: CA_ISSUER_NAME,
      thisUpdate: thisUpdate.toISOString(),
      nextUpdate: nextUpdate.toISOString(),
      revokedSerials: revoked.map((r) => r.certificateId),
    };
    const canonicalPayload = canonicalStringify(payload);
    const signature = crypto
      .sign("RSA-SHA256", Buffer.from(canonicalPayload, "utf8"), privateKey)
      .toString("base64");

    return { ...payload, signature };
  });
}

/**
 * The Certificate Revocation List: every certificate the CA has revoked,
 * most recent first. Any stakeholder can fetch this to check a signer's
 * standing independently of a specific transaction — the standard PKI
 * pattern of publishing revocations rather than requiring a live per-cert
 * query against the CA for every check.
 */
export async function getCRL(): Promise<RevokedCertificateSummary[]> {
  const revoked = await prisma.certificate.findMany({
    where: { revoked: true },
    include: { subject: { select: { name: true } } },
    orderBy: { revokedAt: "desc" },
  });

  return revoked.map((cert) => ({
    certificateId: cert.id,
    subjectUserId: cert.subjectUserId,
    subjectName: cert.subject.name,
    role: cert.role,
    fingerprint: cert.fingerprint,
    revokedAt: (cert.revokedAt ?? cert.issuedAt).toISOString(),
    revokedReason: cert.revokedReason,
    revokedByUserId: cert.revokedByUserId,
  }));
}

// ---------------------------------------------------------------------------
// 4. ADMIN BOOTSTRAP KEY PAIR GENERATION
// ---------------------------------------------------------------------------

/**
 * Generates a fresh RSA-2048 key pair. ONLY used by scripts/create-first-admin.ts
 * (and scripts/test-ca.ts for demonstration) — every normal user
 * (Landowner / Village Officer / Registrar) generates their own key pair
 * in the browser instead (frontend/src/lib/clientCrypto.ts) and never
 * sends the private key to the server at all; see
 * verifyRegistrationProof() below. An ADMIN account never signs anything,
 * so its private key is generated once for certificate issuance and then
 * discarded — nothing wraps or stores it, since there's nothing to use it
 * for afterwards.
 */
export function generateUserKeyPair(): KeyPairPem {
  return generateRsaKeyPair();
}

// ---------------------------------------------------------------------------
// 5. REGISTRATION PROOF OF POSSESSION (client-side keys)
// ---------------------------------------------------------------------------
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

export function verifyRegistrationProof(
  input: RegistrationProofInput,
): RegistrationProofResult {
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

  const canonical = canonicalStringify({
    email: input.email,
    fingerprint,
    timestamp: input.timestamp,
  });
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
