// frontend/src/lib/certificateVerify.ts
//
// Client-side certificate + CRL verification — entirely in the browser,
// using WebCrypto. This is the ONLY place that decides whether a
// certificate is trustworthy for display on the Certificate Lookup page:
// the server's lookup responses carry no "valid"/"reason" verdict at all
// (see routes/certificates.ts's /serial/:id and /crl/signed) specifically
// so there is nothing server-computed to blindly trust here.
//
// Four independent checks, matching lib/ca.ts's own verifyCertificate()
// logic but re-run from scratch against data the browser fetched itself:
//   1. signature      — the certificate's CA signature verifies against
//                        the CA's own public key.
//   2. validity        — the current time is within [issuedAt, expiresAt].
//   3. crlFreshness    — the CRL's own CA signature verifies, and the
//                        current time has not passed the CRL's nextUpdate.
//   4. revocation      — the certificate's serial is not present in the
//                        CRL's revokedSerials list.
// All four are computed unconditionally (never short-circuited) so the UI
// can show a per-step ✓/✗ even when an earlier step already failed.
//
// Domain separation: the CRL payload includes an explicit `type: "CRL"`
// field that the certificate payload deliberately does NOT have — see the
// long comment on getSignedCRL() in lib/ca.ts for why retrofitting an
// equivalent tag onto certificates would invalidate every certificate
// already issued, and why the two payloads' already-disjoint field sets
// make that safe to leave as-is for certificates.

import { canonicalStringify } from "./canonicalize.ts";

const RSA_VERIFY_ALGORITHM = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as const;

export interface CertificateEnvelope {
  serial: string;
  subject: string;
  name: string;
  role: string;
  publicKey: string;
  issuer: string;
  issuedAt: string;
  expiresAt: string;
  signature: string;
}

export interface SignedCRL {
  type: "CRL";
  issuer: string;
  thisUpdate: string;
  nextUpdate: string;
  revokedSerials: string[];
  signature: string;
}

export type VerifyStepId = "signature" | "validity" | "crlFreshness" | "revocation";

export interface VerifyStep {
  id: VerifyStepId;
  label: string;
  pass: boolean;
  detail: string;
}

export interface VerifyResult {
  valid: boolean;
  steps: VerifyStep[];
  failingStep: VerifyStepId | null;
}

function base64ToBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/** PEM -> DER (strips the header/footer lines and whitespace, base64-decodes
 * the rest) -> a non-extractable, verify-only CryptoKey. The inverse of
 * exportPublicKeySpkiPem() in clientCrypto.ts, which this file does not
 * import from — this helper only ever IMPORTS someone else's public key
 * to verify a signature, never touches key generation/signing/wrapping. */
async function importSpkiPublicKeyPem(pem: string): Promise<CryptoKey> {
  const der = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s+/g, "");
  return crypto.subtle.importKey("spki", base64ToBuffer(der), RSA_VERIFY_ALGORITHM, false, ["verify"]);
}

async function verifySignatureBytes(
  publicKeyPem: string,
  canonicalPayload: string,
  signatureBase64: string,
): Promise<boolean> {
  try {
    const key = await importSpkiPublicKeyPem(publicKeyPem);
    const signatureBytes = base64ToBuffer(signatureBase64);
    return await crypto.subtle.verify(
      RSA_VERIFY_ALGORITHM,
      key,
      signatureBytes,
      new TextEncoder().encode(canonicalPayload),
    );
  } catch {
    // A malformed PEM/signature/base64 value is itself a verification
    // failure, not an error the caller should have to handle separately.
    return false;
  }
}

function step(id: VerifyStepId, label: string, pass: boolean, detail: string): VerifyStep {
  return { id, label, pass, detail };
}

/**
 * Verifies one certificate against one CA public key and one signed CRL —
 * all three already fetched by the caller (see api/certificates.ts). Never
 * makes a network request itself, and never trusts any verdict field the
 * server might have attached to any of its three inputs (there isn't one,
 * by design, but this function wouldn't look at it even if there were).
 */
export async function verifyCertificateClientSide(
  certificate: CertificateEnvelope,
  caPublicKeyPem: string,
  crl: SignedCRL,
): Promise<VerifyResult> {
  // 1. Signature — rebuild the EXACT payload lib/ca.ts's
  // buildCertificatePayload() signed (same key set, same key order is
  // irrelevant since canonicalStringify sorts keys itself).
  const certificatePayload = {
    subject: certificate.subject,
    name: certificate.name,
    role: certificate.role,
    publicKey: certificate.publicKey,
    issuer: certificate.issuer,
    issuedAt: certificate.issuedAt,
    expiresAt: certificate.expiresAt,
  };
  const signatureValid = await verifySignatureBytes(
    caPublicKeyPem,
    canonicalStringify(certificatePayload),
    certificate.signature,
  );

  // 2. Validity window.
  const now = Date.now();
  const issuedAtMs = Date.parse(certificate.issuedAt);
  const expiresAtMs = Date.parse(certificate.expiresAt);
  const withinValidityWindow = now >= issuedAtMs && now <= expiresAtMs;

  // 3. CRL freshness — its OWN signature must verify (over its full
  // payload including the "type":"CRL" tag), and "now" must not be past
  // its stated nextUpdate. A CRL that fails either check can't be trusted
  // to answer the revocation question at all, regardless of what it says.
  const crlPayload = {
    type: crl.type,
    issuer: crl.issuer,
    thisUpdate: crl.thisUpdate,
    nextUpdate: crl.nextUpdate,
    revokedSerials: crl.revokedSerials,
  };
  const crlSignatureValid = await verifySignatureBytes(
    caPublicKeyPem,
    canonicalStringify(crlPayload),
    crl.signature,
  );
  const crlNotExpired = now <= Date.parse(crl.nextUpdate);
  const crlFresh = crlSignatureValid && crlNotExpired;

  // 4. Revocation — only meaningful if the CRL itself is trustworthy;
  // reported as its own step regardless, so the UI can show *why* (a
  // revoked serial vs. an untrustworthy CRL are different failure
  // reasons a viewer should be able to tell apart).
  const isRevoked = crl.revokedSerials.includes(certificate.serial);

  const steps: VerifyStep[] = [
    step(
      "signature",
      "Signature",
      signatureValid,
      signatureValid
        ? "The CA's signature over this certificate verifies."
        : "The CA's signature does not match this certificate's contents — it is forged or has been tampered with.",
    ),
    step(
      "validity",
      "Validity",
      withinValidityWindow,
      withinValidityWindow
        ? `Valid from ${certificate.issuedAt} to ${certificate.expiresAt}.`
        : now < issuedAtMs
          ? "This certificate is not yet valid."
          : `This certificate expired on ${certificate.expiresAt}.`,
    ),
    step(
      "crlFreshness",
      "CRL freshness",
      crlFresh,
      !crlSignatureValid
        ? "The revocation list's own CA signature does not verify — its contents cannot be trusted."
        : crlNotExpired
          ? `Revocation list is current (valid until ${crl.nextUpdate}).`
          : `Revocation list expired on ${crl.nextUpdate} — a newer one is needed before revocation can be checked.`,
    ),
    step(
      "revocation",
      "Revocation",
      !isRevoked,
      isRevoked
        ? "This certificate's serial appears on the revocation list."
        : "This certificate's serial does not appear on the revocation list.",
    ),
  ];

  const failing = steps.find((s) => !s.pass) ?? null;

  return {
    valid: steps.every((s) => s.pass),
    steps,
    failingStep: failing ? failing.id : null,
  };
}
