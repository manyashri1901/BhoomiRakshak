// scripts/test-certificate-verify-client.ts
//
// Exercises the ACTUAL frontend verify helper (frontend/src/lib/
// certificateVerify.ts) — not a reimplementation — against real data from
// a running server: a genuine certificate, a tampered one, a revoked one,
// and the real signed CRL. This is the single most important check for
// the Certificate Lookup rework, since it's the one place client-side
// WebCrypto verification logic has to agree with what the server actually
// signed, byte for byte.
//
// Run with: node scripts/test-certificate-verify-client.ts
// (server must already be running: node server.ts)

import "dotenv/config";
import assert from "node:assert/strict";
import {
  generateKeyPair,
  exportPublicKeySpkiPem,
  fingerprintOfPem,
  wrapPrivateKey,
  signCanonicalString,
} from "../frontend/src/lib/clientCrypto.ts";
import { canonicalStringify } from "../frontend/src/lib/canonicalize.ts";
import { verifyCertificateClientSide, type CertificateEnvelope } from "../frontend/src/lib/certificateVerify.ts";

const BASE = "http://localhost:4000/api";
const PASSWORD = "verifyclienttest123";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL ?? "shrimanya2@gmail.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD ?? "AdminPass123!";

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
  const adminLogin = await api("/auth/login", null, "POST", { email: ADMIN_EMAIL, password: ADMIN_PASSWORD });
  if (adminLogin.status !== 200) {
    throw new Error(`Admin login failed: ${JSON.stringify(adminLogin.data)}`);
  }
  const adminToken = adminLogin.data.token as string;

  const caInfo = await api("/certificates/ca", user.token);
  const legacyCert = await api(`/certificates/${user.id}`, user.token);
  const serial = legacyCert.data.id as string;

  // --- 1. Genuine, unrevoked certificate: every step should pass. -------
  {
    const cert = await api(`/certificates/serial/${serial}`, user.token);
    const crl = await api("/certificates/crl/signed", user.token);
    const result = await verifyCertificateClientSide(
      cert.data as CertificateEnvelope,
      caInfo.data.publicKey,
      crl.data,
    );
    check("genuine certificate: overall valid", result.valid === true);
    check(
      "genuine certificate: all 4 steps pass",
      result.steps.every((s) => s.pass) && result.steps.length === 4,
    );
    check("genuine certificate: failingStep is null", result.failingStep === null);
  }

  // --- 2. Tampered certificate (public key swapped client-side after the
  //        fact) — signature step must fail, nothing else should be
  //        trusted to mask it. ------------------------------------------
  {
    const cert = (await api(`/certificates/serial/${serial}`, user.token)).data as CertificateEnvelope;
    const otherKeyPair = await generateKeyPair();
    const tamperedPublicKey = await exportPublicKeySpkiPem(otherKeyPair.publicKey);
    const tamperedCert: CertificateEnvelope = { ...cert, publicKey: tamperedPublicKey };
    const crl = await api("/certificates/crl/signed", user.token);
    const result = await verifyCertificateClientSide(tamperedCert, caInfo.data.publicKey, crl.data);
    check("tampered certificate: overall invalid", result.valid === false);
    check("tampered certificate: failingStep is 'signature'", result.failingStep === "signature");
    const sigStep = result.steps.find((s) => s.id === "signature");
    check("tampered certificate: signature step explicitly fails", sigStep?.pass === false);
  }

  // --- 3. Revoked certificate — revocation step must fail; signature and
  //        validity should still independently pass (it's a genuine,
  //        unexpired certificate that has simply been revoked). ---------
  {
    const revokeRes = await api(`/certificates/${legacyCert.data.id}/revoke`, adminToken, "POST", {
      reason: "test-certificate-verify-client.ts",
    });
    assert.equal(revokeRes.status, 200, `revoke call failed: ${JSON.stringify(revokeRes.data)}`);

    const cert = (await api(`/certificates/serial/${serial}`, user.token)).data as CertificateEnvelope;
    const crl = await api("/certificates/crl/signed", user.token);
    const result = await verifyCertificateClientSide(cert, caInfo.data.publicKey, crl.data);
    check("revoked certificate: overall invalid", result.valid === false);
    check("revoked certificate: failingStep is 'revocation'", result.failingStep === "revocation");
    check(
      "revoked certificate: signature step still independently passes",
      result.steps.find((s) => s.id === "signature")?.pass === true,
    );
    check(
      "revoked certificate: validity step still independently passes",
      result.steps.find((s) => s.id === "validity")?.pass === true,
    );
  }

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
