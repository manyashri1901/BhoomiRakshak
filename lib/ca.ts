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

/**
 * Loads the root CA key pair from disk, generating it on first run.
 *
 * This is the CA's own identity: every certificate issued by
 * issueCertificate() is signed with `privateKey`, and every verification in
 * verifyCertificate() checks against `publicKey`. Losing ca-private.pem
 * means losing the ability to issue new trusted certificates; leaking it
 * means an attacker could forge certificates, so keys/ must never be
 * committed to git (see .gitignore).
 */
export function ensureRootCA(): KeyPairPem {
  if (cachedRootCA) return cachedRootCA;

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
  // passwordHash and the raw RSA privateKeyRef, neither of which this
  // function (or its callers, some of which return its result to clients)
  // should ever pull into memory.
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
// 4. USER KEY PAIR GENERATION (registration flow)
// ---------------------------------------------------------------------------

/**
 * Generates a fresh RSA-2048 key pair for a newly registering user
 * (Landowner / Village Officer / Registrar). Called once at registration,
 * before issueCertificate() binds the resulting public key to the user's
 * identity. The private key is the user's own — BhoomiRakshak never signs
 * on their behalf; only the CA's own key pair (see ensureRootCA) is
 * held server-side for issuing certificates.
 */
export function generateUserKeyPair(): KeyPairPem {
  return generateRsaKeyPair();
}

// ---------------------------------------------------------------------------
// 5. PROOF OF POSSESSION
// ---------------------------------------------------------------------------
//
// issueCertificate() trusts whatever public key it is handed. Without this
// check, nothing stops a registration request from submitting a public key
// it doesn't actually control the matching private key for (e.g. someone
// else's public key, or a corrupted keypair) — the CA would then issue a
// certificate binding an identity to a key the registrant can never sign
// with, or worse, to a key someone else controls. Proof of possession
// closes that gap: the server generates a random nonce, has the *private*
// key sign it, and immediately checks that signature with the *public*
// key. Only someone holding the matching private key can produce a
// signature the public key accepts.

export interface KeyPossessionProof {
  nonce: string;
  signature: string;
}

/**
 * Signs a fresh random nonce with `privateKey`, proving whoever calls this
 * holds that private key. Called right after generateUserKeyPair() during
 * registration, before the resulting public key is ever handed to
 * issueCertificate().
 */
export function proveKeyPossession(privateKey: string): KeyPossessionProof {
  // 32 random bytes, hex-encoded — large enough that guessing/replaying a
  // previously seen nonce is infeasible, and it's never reused across calls.
  const nonce = crypto.randomBytes(32).toString("hex");
  const signature = crypto
    .sign("RSA-SHA256", Buffer.from(nonce, "utf8"), privateKey)
    .toString("base64");
  return { nonce, signature };
}

/**
 * Verifies a proof produced by proveKeyPossession(): does `signature` over
 * `nonce` check out against `publicKey`? Returns false (never throws) on a
 * malformed key or signature so callers can treat it as a plain pass/fail
 * gate on registration.
 */
export function verifyKeyPossession(
  publicKey: string,
  nonce: string,
  signature: string,
): boolean {
  try {
    return crypto.verify(
      "RSA-SHA256",
      Buffer.from(nonce, "utf8"),
      publicKey,
      Buffer.from(signature, "base64"),
    );
  } catch {
    // Malformed PEM / base64 — treat as failed proof, not a crash.
    return false;
  }
}
