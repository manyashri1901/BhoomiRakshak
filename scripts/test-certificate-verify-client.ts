// scripts/test-certificate-verify-client.ts
//
// Exercises the ACTUAL frontend verify helper (frontend/src/lib/
// certificateVerify.ts) — not a reimplementation — against real data from
// a running server: a genuine certificate, a tampered one, a backdated
// (expired) one, a revoked one, a certificate chained to a forged
// intermediate CA, a CRL signed by the wrong key, and a stale CRL. This is
// the single most important check for the Certificate Lookup rework,
// since it's the one place client-side WebCrypto verification logic has
// to agree with what the server actually signed, byte for byte.
//
// Forged inputs (tampered cert, expired cert, forged intermediate, wrong-
// key CRL, stale CRL) are built directly with @peculiar/x509 in this
// script — the same library the real verify code uses, imported from the
// same node_modules copy — rather than re-derived through HTTP, since the
// server itself has no reason to ever hand out a forged certificate. The
// genuine/revoked cases still round-trip through the real running server.
//
// Run with: node scripts/test-certificate-verify-client.ts
// (server must already be running: node server.ts)

import "dotenv/config";
// Must precede the "@peculiar/x509" import below: its tsyringe dependency
// requires this polyfill at load time, not just before first use.
import "reflect-metadata";
import * as crypto from "node:crypto";
import { webcrypto } from "node:crypto";
import * as x509 from "@peculiar/x509";
import {
  generateKeyPair,
  exportPublicKeySpkiPem,
  fingerprintOfPem,
  wrapPrivateKey,
  signCanonicalString,
} from "../frontend/src/lib/clientCrypto.ts";
import { canonicalStringify } from "../frontend/src/lib/canonicalize.ts";
import {
  verifyCertificateClientSide,
  type CertificateEnvelope,
  type CAInfo,
  type SignedCRL,
} from "../frontend/src/lib/certificateVerify.ts";
import { ensureIssuingCA, revokeCertificate, getSignedCRL } from "../lib/ca.ts";
import { RSA_SIGNING_ALGORITHM } from "../lib/x509Keys.ts";

const BASE = "http://localhost:4000/api";
const PASSWORD = "verifyclienttest123";

function randomSerialHex(): string {
  const bytes = crypto.randomBytes(16);
  bytes[0] &= 0x7f; // keep the ASN.1 INTEGER positive without library padding
  return bytes.toString("hex");
}

async function api(path: string, token: string | null, method = "GET", body?: unknown) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => null);
  return { status: res.status, data };
}

async function registerUser(name: string, email: string) {
  const keyPair = await generateKeyPair();
  const publicKeyPem = await exportPublicKeySpkiPem(keyPair.publicKey);
  const fingerprint = await fingerprintOfPem(publicKeyPem);
  const proofTimestamp = new Date().toISOString();
  const canonicalProof = canonicalStringify({ email, fingerprint, timestamp: proofTimestamp });
  const proofSignature = await signCanonicalString(keyPair.privateKey, canonicalProof);
  const wrapped = await wrapPrivateKey(keyPair.privateKey, PASSWORD);

  const registerRes = await fetch(`${BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name,
      email,
      password: PASSWORD,
      role: "LANDOWNER",
      publicKey: publicKeyPem,
      proofTimestamp,
      proofSignature,
      wrappedPrivateKey: wrapped.ciphertext,
      wrapSalt: wrapped.salt,
      wrapIv: wrapped.iv,
    }),
  });
  const registerBody = await registerRes.json();
  if (registerRes.status !== 201) throw new Error(`Registration failed: ${JSON.stringify(registerBody)}`);

  const loginRes = await fetch(`${BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: PASSWORD }),
  });
  const loginBody = await loginRes.json();
  return { id: registerBody.id as string, token: loginBody.token as string };
}

async function main() {
  const stamp = Date.now();
  let failures = 0;
  function check(label: string, pass: boolean) {
    console.log(`${pass ? "PASS" : "FAIL"} — ${label}`);
    if (!pass) failures += 1;
  }

  const user = await registerUser("Verify Client Test", `verify-client-${stamp}@example.com`);

  const caInfo = (await api("/certificates/ca", user.token)).data as CAInfo;
  const legacyCert = await api(`/certificates/${user.id}`, user.token);
  const serial = legacyCert.data.serialNumber as string;
  const certificateId = legacyCert.data.id as string;

  async function fetchGenuineEnvelope(): Promise<CertificateEnvelope> {
    return (await api(`/certificates/serial/${serial}`, user.token)).data as CertificateEnvelope;
  }
  async function fetchGenuineCrl(): Promise<SignedCRL> {
    return (await api("/certificates/crl/signed", user.token)).data as SignedCRL;
  }

  // --- 1. Genuine, unrevoked certificate: every step should pass. -------
  {
    const envelope = await fetchGenuineEnvelope();
    const crl = await fetchGenuineCrl();
    const result = await verifyCertificateClientSide(envelope, caInfo, crl);
    check("genuine certificate: overall valid", result.valid === true);
    check(
      "genuine certificate: all 5 steps pass",
      result.steps.every((s) => s.pass) && result.steps.length === 5,
    );
    check("genuine certificate: failingStep is null", result.failingStep === null);
  }

  // --- 2. Tampered certificate — attacker swaps in a self-signed forgery
  //        for a DIFFERENT key pair, same subject/serial. The Issuing CA
  //        never signed this object, so the signatures step must fail. ---
  {
    const envelope = await fetchGenuineEnvelope();
    const existingCert = new x509.X509Certificate(envelope.certificatePem);
    const otherKeys = (await webcrypto.subtle.generateKey(RSA_SIGNING_ALGORITHM, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const forged = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: existingCert.serialNumber,
      name: existingCert.subject,
      notBefore: existingCert.notBefore,
      notAfter: existingCert.notAfter,
      signingAlgorithm: RSA_SIGNING_ALGORITHM,
      keys: otherKeys,
    });
    const tampered: CertificateEnvelope = { ...envelope, certificatePem: forged.toString("pem") };
    const crl = await fetchGenuineCrl();
    const result = await verifyCertificateClientSide(tampered, caInfo, crl);
    check("tampered certificate: overall invalid", result.valid === false);
    check(
      "tampered certificate: signatures step explicitly fails",
      result.steps.find((s) => s.id === "signatures")?.pass === false,
    );
  }

  // --- 3. Expired certificate — the SAME subject/public key, genuinely
  //        re-signed by the real Issuing CA but with a backdated validity
  //        window. Not forged: just naturally past its window. ----------
  {
    const envelope = await fetchGenuineEnvelope();
    const existingCert = new x509.X509Certificate(envelope.certificatePem);
    const { issuingPrivateKey, issuingCert } = await ensureIssuingCA();

    const notBefore = new Date(Date.now() - 2 * 365 * 24 * 60 * 60 * 1000);
    const notAfter = new Date(notBefore.getTime() + 365 * 24 * 60 * 60 * 1000);
    const backdated = await x509.X509CertificateGenerator.create({
      serialNumber: randomSerialHex(),
      subject: existingCert.subject,
      issuer: issuingCert.subject,
      notBefore,
      notAfter,
      signingAlgorithm: RSA_SIGNING_ALGORITHM,
      publicKey: existingCert.publicKey,
      signingKey: issuingPrivateKey,
      extensions: [
        new x509.BasicConstraintsExtension(false),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature),
      ],
    });
    const expiredEnvelope: CertificateEnvelope = { ...envelope, certificatePem: backdated.toString("pem") };
    const crl = await fetchGenuineCrl();
    const result = await verifyCertificateClientSide(expiredEnvelope, caInfo, crl);
    check("expired certificate: overall invalid", result.valid === false);
    check(
      "expired certificate: validity step explicitly fails",
      result.steps.find((s) => s.id === "validity")?.pass === false,
    );
    check(
      "expired certificate: signatures step still independently passes (genuinely signed, just expired)",
      result.steps.find((s) => s.id === "signatures")?.pass === true,
    );
  }

  // --- 4. Revoked certificate — revocation step must fail; signatures and
  //        validity should still independently pass (it's a genuine,
  //        unexpired certificate that has simply been revoked). Revokes
  //        directly via lib/ca.ts rather than the HTTP admin-only route
  //        (routes/certificates.ts requires requireRole("ADMIN")) — this
  //        script tests verifyCertificateClientSide(), not the HTTP route's
  //        auth, and direct revocation removes any dependency on knowing a
  //        real admin's credentials (same pattern test/certificate.test.ts
  //        already uses: revokedByUserId can be the subject's own id). The
  //        CRL is also fetched directly via getSignedCRL() here rather
  //        than fetchGenuineCrl()'s HTTP round trip — the running server
  //        (a separate process) caches its signed CRL in memory for 3
  //        minutes, and revokeCertificate()'s cache invalidation only
  //        clears THIS process's copy of that cache, not the server's. ---
  {
    await revokeCertificate({
      certificateId,
      revokedByUserId: user.id,
      reason: "test-certificate-verify-client.ts",
    });

    const envelope = await fetchGenuineEnvelope();
    const crl = await getSignedCRL();
    const result = await verifyCertificateClientSide(envelope, caInfo, crl);
    check("revoked certificate: overall invalid", result.valid === false);
    check(
      "revoked certificate: revocation step explicitly fails",
      result.steps.find((s) => s.id === "revocation")?.pass === false,
    );
    check(
      "revoked certificate: signatures step still independently passes",
      result.steps.find((s) => s.id === "signatures")?.pass === true,
    );
    check(
      "revoked certificate: validity step still independently passes",
      result.steps.find((s) => s.id === "validity")?.pass === true,
    );
  }

  // --- 5. Forged intermediate — a completely unrelated "CA" (never
  //        trusted by this app's real root) issues a certificate for the
  //        SAME subject/key, and the envelope's issuingCertificatePem is
  //        swapped for this fake intermediate. Both the structural
  //        (issuerChain) and cryptographic (signatures) checks must catch
  //        this independently — the real root certificate from caInfo is
  //        left untouched throughout. -----------------------------------
  {
    const envelope = await fetchGenuineEnvelope();
    const existingCert = new x509.X509Certificate(envelope.certificatePem);

    const fakeIssuingKeys = (await webcrypto.subtle.generateKey(RSA_SIGNING_ALGORITHM, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const fakeIssuingCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: randomSerialHex(),
      name: "CN=Fake Issuing CA,O=Not A Trusted Authority",
      notBefore: new Date(Date.now() - 24 * 60 * 60 * 1000),
      notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
      signingAlgorithm: RSA_SIGNING_ALGORITHM,
      keys: fakeIssuingKeys,
    });
    const forgedUserCert = await x509.X509CertificateGenerator.create({
      serialNumber: randomSerialHex(),
      subject: existingCert.subject,
      issuer: fakeIssuingCert.subject,
      notBefore: existingCert.notBefore,
      notAfter: existingCert.notAfter,
      signingAlgorithm: RSA_SIGNING_ALGORITHM,
      publicKey: existingCert.publicKey,
      signingKey: fakeIssuingKeys.privateKey,
      extensions: [
        new x509.BasicConstraintsExtension(false),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature),
      ],
    });
    const forgedEnvelope: CertificateEnvelope = {
      ...envelope,
      certificatePem: forgedUserCert.toString("pem"),
      issuingCertificatePem: fakeIssuingCert.toString("pem"),
    };
    const crl = await fetchGenuineCrl();
    const result = await verifyCertificateClientSide(forgedEnvelope, caInfo, crl);
    check("forged intermediate: overall invalid", result.valid === false);
    check(
      "forged intermediate: issuerChain step explicitly fails (fake issuer never links to the real root)",
      result.steps.find((s) => s.id === "issuerChain")?.pass === false,
    );
    check(
      "forged intermediate: signatures step explicitly fails (fake issuing cert never verifies against the real root key)",
      result.steps.find((s) => s.id === "signatures")?.pass === false,
    );
  }

  // --- 6. CRL signed by the wrong key — a genuine certificate, but the CRL
  //        handed to the verifier was signed by a key that is NOT the real
  //        Issuing CA's. crlFreshness must fail on signature grounds,
  //        while every certificate-only step still independently passes. -
  {
    const envelope = await fetchGenuineEnvelope();
    const wrongKeys = (await webcrypto.subtle.generateKey(RSA_SIGNING_ALGORITHM, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const issuingCert = new x509.X509Certificate(envelope.issuingCertificatePem);
    const forgedCrl = await x509.X509CrlGenerator.create({
      issuer: issuingCert.subject,
      thisUpdate: new Date(),
      nextUpdate: new Date(Date.now() + 60 * 60 * 1000),
      signingAlgorithm: RSA_SIGNING_ALGORITHM,
      signingKey: wrongKeys.privateKey, // NOT the real Issuing CA's key
      entries: [],
    });
    const badCrl: SignedCRL = {
      pem: forgedCrl.toString("pem"),
      thisUpdate: forgedCrl.thisUpdate.toISOString(),
      nextUpdate: forgedCrl.nextUpdate!.toISOString(),
    };
    const result = await verifyCertificateClientSide(envelope, caInfo, badCrl);
    check("CRL signed by wrong key: overall invalid", result.valid === false);
    check(
      "CRL signed by wrong key: crlFreshness step explicitly fails",
      result.steps.find((s) => s.id === "crlFreshness")?.pass === false,
    );
    check(
      "CRL signed by wrong key: signatures step still independently passes (the certificate itself is untouched)",
      result.steps.find((s) => s.id === "signatures")?.pass === true,
    );
  }

  // --- 7. Stale CRL — genuinely signed by the real Issuing CA, but its own
  //        nextUpdate is already in the past. Distinguishable from the
  //        wrong-key case above: the signature is trustworthy, only the
  //        freshness window has lapsed. ----------------------------------
  {
    const envelope = await fetchGenuineEnvelope();
    const { issuingPrivateKey, issuingCert } = await ensureIssuingCA();
    const staleThisUpdate = new Date(Date.now() - 2 * 60 * 60 * 1000);
    const staleNextUpdate = new Date(staleThisUpdate.getTime() + 60 * 60 * 1000); // expired an hour ago
    const staleCrlRaw = await x509.X509CrlGenerator.create({
      issuer: issuingCert.subject,
      thisUpdate: staleThisUpdate,
      nextUpdate: staleNextUpdate,
      signingAlgorithm: RSA_SIGNING_ALGORITHM,
      signingKey: issuingPrivateKey,
      entries: [],
    });
    const staleCrl: SignedCRL = {
      pem: staleCrlRaw.toString("pem"),
      thisUpdate: staleThisUpdate.toISOString(),
      nextUpdate: staleNextUpdate.toISOString(),
    };
    const result = await verifyCertificateClientSide(envelope, caInfo, staleCrl);
    check("stale CRL: overall invalid", result.valid === false);
    check(
      "stale CRL: crlFreshness step explicitly fails",
      result.steps.find((s) => s.id === "crlFreshness")?.pass === false,
    );
    check(
      "stale CRL: crlFreshness failure is distinguishable as staleness, not a bad signature",
      (result.steps.find((s) => s.id === "crlFreshness")?.detail ?? "").toLowerCase().includes("expired"),
    );
    check(
      "stale CRL: signatures step still independently passes",
      result.steps.find((s) => s.id === "signatures")?.pass === true,
    );
  }

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
