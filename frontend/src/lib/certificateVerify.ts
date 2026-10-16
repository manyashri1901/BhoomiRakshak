// frontend/src/lib/certificateVerify.ts
//
// Client-side X.509 certificate + CRL verification — entirely in the
// browser, using @peculiar/x509 (no hand-rolled ASN.1 anywhere in this
// codebase; see lib/ca.ts on the backend for the matching issuance side).
// This is the ONLY place that decides whether a certificate is
// trustworthy for display on the Certificate Lookup page: the server's
// lookup responses carry no "valid"/"reason" verdict at all (see
// routes/certificates.ts's /serial/:serial and /crl/signed) specifically
// so there is nothing server-computed to blindly trust here.
//
// Five independent checks, never short-circuited, so the UI can show a
// per-step ✓/✗ even when an earlier step already failed:
//   1. issuerChain    — the certificate NAMES link up correctly (user's
//                       issuer = issuing CA's subject; issuing CA's
//                       issuer = root's subject; root is self-issued).
//                       A purely structural check, independent of whether
//                       any signature is genuine — see "signatures" below
//                       for that.
//   2. signatures     — the user certificate's signature verifies against
//                       the issuing CA's public key, AND the issuing CA's
//                       own certificate's signature verifies against the
//                       root's public key.
//   3. validity        — the current time is within [notBefore, notAfter]
//                       for the user certificate, the issuing CA
//                       certificate, AND the root certificate.
//   4. crlFreshness    — the CRL's own CA signature verifies (against the
//                       issuing CA), and the current time has not passed
//                       the CRL's nextUpdate.
//   5. revocation      — neither the user certificate's serial NOR the
//                       issuing CA's own certificate's serial appears in
//                       the CRL's revoked list.

import "./x509Setup.ts";
import * as x509 from "@peculiar/x509";

export interface CertificateEnvelope {
  serialNumber: string;
  certificatePem: string;
  issuingCertificatePem: string;
}

export interface CAInfo {
  rootCertPem: string;
  issuingCertPem: string;
  fingerprint: string;
}

export interface SignedCRL {
  pem: string;
  thisUpdate: string;
  nextUpdate: string;
}

export type VerifyStepId = "issuerChain" | "signatures" | "validity" | "crlFreshness" | "revocation";

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
  // Surfaced for display (item 8: "Show serial number and fingerprint").
  serialNumber: string;
  fingerprint: string;
  subject: string;
}

function step(id: VerifyStepId, label: string, pass: boolean, detail: string): VerifyStep {
  return { id, label, pass, detail };
}

async function fingerprintOf(cert: x509.X509Certificate): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", cert.rawData);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Verifies one user certificate against the issuing + root CA
 * certificates and one signed CRL — all fetched by the caller (see
 * api/certificates.ts). Never makes a network request itself, and never
 * trusts any verdict field the server might have attached to any of its
 * inputs (there isn't one, by design, but this function wouldn't look at
 * it even if there were).
 */
export async function verifyCertificateClientSide(
  envelope: CertificateEnvelope,
  caInfo: CAInfo,
  signedCrl: SignedCRL,
): Promise<VerifyResult> {
  const userCert = new x509.X509Certificate(envelope.certificatePem);
  const issuingCert = new x509.X509Certificate(envelope.issuingCertificatePem);
  const rootCert = new x509.X509Certificate(caInfo.rootCertPem);

  // 1. Issuer chain — names only, deliberately checked independently of
  // any signature: a forged certificate could print ANY issuer name it
  // likes, so this step alone proves nothing on its own, but a MISMATCH
  // here means the chain is structurally broken regardless of what the
  // signature step finds.
  const userLinksToIssuing = userCert.issuer === issuingCert.subject;
  const issuingLinksToRoot = issuingCert.issuer === rootCert.subject;
  const rootIsSelfIssued = rootCert.issuer === rootCert.subject;
  const issuerChainValid = userLinksToIssuing && issuingLinksToRoot && rootIsSelfIssued;

  // 2. Signatures — the actual cryptographic proof behind each link above.
  // signatureOnly: true is required here — @peculiar/x509's X509Certificate
  // .verify() otherwise ALSO folds in the certificate's own notBefore/
  // notAfter window by default and silently returns false for a genuinely,
  // correctly signed but merely-expired certificate, which would make this
  // step indistinguishable from an actually forged signature. "validity"
  // below is the step responsible for the time window; this step is
  // deliberately pure cryptography only.
  const userSignatureValid = await userCert.verify({ publicKey: issuingCert.publicKey, signatureOnly: true });
  const issuingSignatureValid = await issuingCert.verify({ publicKey: rootCert.publicKey, signatureOnly: true });
  const signaturesValid = userSignatureValid && issuingSignatureValid;

  // 3. Validity — all three certificates, independently.
  const now = new Date();
  const userWithinWindow = now >= userCert.notBefore && now <= userCert.notAfter;
  const issuingWithinWindow = now >= issuingCert.notBefore && now <= issuingCert.notAfter;
  const rootWithinWindow = now >= rootCert.notBefore && now <= rootCert.notAfter;
  const validityValid = userWithinWindow && issuingWithinWindow && rootWithinWindow;

  // 4. CRL freshness — its own signature must verify (against the issuing
  // CA), and "now" must not be past its stated nextUpdate.
  const crl = new x509.X509Crl(signedCrl.pem);
  const crlSignatureValid = await crl.verify({ publicKey: issuingCert.publicKey });
  const crlNotExpired = now <= (crl.nextUpdate ?? new Date(0));
  const crlFreshValid = crlSignatureValid && crlNotExpired;

  // 5. Revocation — both the user certificate's serial and the issuing
  // CA's own serial are checked against the CRL; only meaningful if the
  // CRL itself is trustworthy (step 4), but reported as its own step
  // regardless, so the UI can show *why* (a revoked serial vs. an
  // untrustworthy CRL are different failure reasons a viewer should be
  // able to tell apart).
  const userRevoked = Boolean(crl.findRevoked(userCert.serialNumber));
  const issuingRevoked = Boolean(crl.findRevoked(issuingCert.serialNumber));
  const revocationValid = !userRevoked && !issuingRevoked;

  const steps: VerifyStep[] = [
    step(
      "issuerChain",
      "Issuer chain",
      issuerChainValid,
      issuerChainValid
        ? `${userCert.subject} -> ${issuingCert.subject} -> ${rootCert.subject} (self-issued).`
        : "The certificate's issuer name does not lead to this root through the issuing CA — the chain is structurally broken.",
    ),
    step(
      "signatures",
      "Signatures",
      signaturesValid,
      signaturesValid
        ? "Both the user certificate's and the Issuing CA's signatures verify."
        : !userSignatureValid
          ? "The user certificate's signature does not verify against the Issuing CA's public key — forged or tampered."
          : "The Issuing CA's own certificate does not verify against the Root CA's public key.",
    ),
    step(
      "validity",
      "Validity",
      validityValid,
      validityValid
        ? `All three certificates are within their validity window (checked at ${now.toISOString()}).`
        : !userWithinWindow
          ? `The user certificate is outside its validity window (${userCert.notBefore.toISOString()} – ${userCert.notAfter.toISOString()}).`
          : !issuingWithinWindow
            ? "The Issuing CA certificate is outside its validity window."
            : "The Root CA certificate is outside its validity window.",
    ),
    step(
      "crlFreshness",
      "CRL freshness",
      crlFreshValid,
      !crlSignatureValid
        ? "The revocation list's own signature does not verify against the Issuing CA — its contents cannot be trusted."
        : crlNotExpired
          ? `Revocation list is current (valid until ${crl.nextUpdate?.toISOString()}).`
          : `Revocation list expired on ${crl.nextUpdate?.toISOString()} — a newer one is needed before revocation can be checked.`,
    ),
    step(
      "revocation",
      "Revocation",
      revocationValid,
      userRevoked
        ? "This certificate's serial appears on the revocation list."
        : issuingRevoked
          ? "The Issuing CA's own certificate appears on the revocation list."
          : "Neither this certificate's serial nor the Issuing CA's own serial appears on the revocation list.",
    ),
  ];

  const failing = steps.find((s) => !s.pass) ?? null;

  return {
    valid: steps.every((s) => s.pass),
    steps,
    failingStep: failing ? failing.id : null,
    serialNumber: userCert.serialNumber,
    fingerprint: await fingerprintOf(userCert),
    subject: userCert.subject,
  };
}
