// scripts/test-client-signing-e2e.ts
//
// Full integration test against a RUNNING server (node server.ts on
// localhost:4000) exercising the real HTTP API exactly as the browser
// would: registers fresh users using the actual client-side crypto module
// (frontend/src/lib/clientCrypto.ts, no mocks), logs in, creates a land
// record, uploads a document, and runs a complete prepare -> sign ->
// submit cycle through all three approval stages. Also exercises every
// required rejection path: replayed nonce, expired nonce, wrong-key
// signature, and a revoked certificate.
//
// Run with: node scripts/test-client-signing-e2e.ts
// (server must already be running: node server.ts)

import "dotenv/config";
import {
  generateKeyPair,
  exportPublicKeySpkiPem,
  fingerprintOfPem,
  wrapPrivateKey,
  unwrapPrivateKey,
  signCanonicalString,
} from "../frontend/src/lib/clientCrypto.ts";
import { canonicalStringify } from "../frontend/src/lib/canonicalize.ts";
import { prisma } from "../lib/prisma.ts";

// No hardcoded fallback credentials — this repo is public. Both must be
// set explicitly, matching a real ADMIN account on whatever database the
// running server is connected to (needed for the revoked-certificate
// rejection check further down).
if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) {
  console.error(
    "Refusing to run: ADMIN_EMAIL and ADMIN_PASSWORD env vars must both be set, matching an " +
      "existing ADMIN account (this script logs in as that admin to revoke a certificate mid-flow).",
  );
  process.exit(1);
}
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const BASE = "http://localhost:4000/api";
const PASSWORD = "testpass123!";

let failures = 0;
function check(label: string, condition: boolean, extra?: unknown) {
  console.log(`${condition ? "PASS" : "FAIL"}: ${label}${extra !== undefined ? ` — ${JSON.stringify(extra)}` : ""}`);
  if (!condition) failures++;
}

interface RegisteredUser {
  id: string;
  email: string;
  token: string;
  wrappedKey: { ciphertext: string; salt: string; iv: string };
  publicKeyPem: string;
  keyPair: CryptoKeyPair;
}

async function registerClientSideUser(name: string, email: string, role: string): Promise<RegisteredUser> {
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
      role,
      publicKey: publicKeyPem,
      proofTimestamp,
      proofSignature,
      wrappedPrivateKey: wrapped.ciphertext,
      wrapSalt: wrapped.salt,
      wrapIv: wrapped.iv,
    }),
  });
  const registerBody = await registerRes.json();
  if (registerRes.status !== 201) {
    throw new Error(`Registration failed for ${email}: ${JSON.stringify(registerBody)}`);
  }

  // grep/network-payload check (item 6): confirm nothing in the request we
  // just sent, or the response we just got back, contains the raw private
  // key — only the wrapped ciphertext and the public key should appear.
  const sentBodyStr = JSON.stringify({
    publicKey: publicKeyPem,
    wrappedPrivateKey: wrapped.ciphertext,
    wrapSalt: wrapped.salt,
    wrapIv: wrapped.iv,
  });
  const pkcs8Raw = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const pkcs8Base64 = Buffer.from(pkcs8Raw).toString("base64");
  check(
    `[${email}] raw private key bytes are NOT present in the registration request body`,
    !sentBodyStr.includes(pkcs8Base64),
  );
  check(
    `[${email}] registration response contains no privateKey/wrappedPrivateKey field`,
    !("wrappedPrivateKey" in registerBody) && !("privateKey" in registerBody),
  );

  const loginRes = await fetch(`${BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: PASSWORD }),
  });
  const loginBody = await loginRes.json();
  if (loginRes.status !== 200) throw new Error(`Login failed for ${email}: ${JSON.stringify(loginBody)}`);

  check(
    `[${email}] login response's wrappedKey is the ciphertext blob, not a raw key`,
    loginBody.wrappedKey.ciphertext === wrapped.ciphertext && !("privateKey" in loginBody),
  );

  return {
    id: registerBody.id,
    email,
    token: loginBody.token,
    wrappedKey: loginBody.wrappedKey,
    publicKeyPem,
    keyPair,
  };
}

async function api(path: string, token: string, method = "GET", body?: unknown) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => null);
  return { status: res.status, data };
}

async function signAndSubmitTest(
  user: RegisteredUser,
  preparePath: string,
  submitPath: string,
): Promise<{ status: number; data: any }> {
  const prepared = await api(preparePath, user.token, "POST");
  if (prepared.status !== 200) throw new Error(`prepare failed: ${JSON.stringify(prepared)}`);
  const privateKey = await unwrapPrivateKey(user.wrappedKey, PASSWORD);
  const signatureValue = await signCanonicalString(privateKey, prepared.data.payload);
  return api(submitPath, user.token, "POST", { nonce: prepared.data.nonce, signatureValue });
}

async function main() {
  const stamp = Date.now();
  const landowner = await registerClientSideUser("E2E Landowner", `e2e-lo-${stamp}@example.com`, "LANDOWNER");
  const vo = await registerClientSideUser("E2E VO", `e2e-vo-${stamp}@example.com`, "VILLAGE_OFFICER");
  const registrar = await registerClientSideUser("E2E Registrar", `e2e-reg-${stamp}@example.com`, "REGISTRAR");
  console.log("Registered 3 client-side-keyed users.\n");

  // --- Set up a land record + uploaded document ---
  const lrRes = await api("/land-records", registrar.token, "POST", {
    surveyNumber: `SN-E2E-${stamp}`,
    location: "E2E Test Village",
    area: 1.5,
    currentOwnerId: landowner.id,
  });
  check("land record created", lrRes.status === 201, lrRes.data);
  const landRecordId = lrRes.data.id;

  const fileContent = `%PDF-1.4\ntest document ${stamp}`;
  const formData = new FormData();
  formData.append("file", new Blob([fileContent], { type: "application/pdf" }), "test.pdf");
  const uploadRes = await fetch(`${BASE}/documents/upload`, {
    method: "POST",
    headers: { Authorization: `Bearer ${landowner.token}` },
    body: formData,
  });
  const uploadBody = await uploadRes.json();
  check("document uploaded", uploadRes.status === 201, uploadBody);

  // --- Stage 1: Landowner prepare -> sign -> submit ---
  const createInput = {
    type: "REGISTRATION",
    landRecordId,
    documentPath: uploadBody.documentPath,
    documentHash: uploadBody.documentHash,
  };
  const prep1 = await api("/transactions/prepare", landowner.token, "POST", createInput);
  check("transaction prepare succeeds", prep1.status === 200, prep1.data);

  const loKey = await unwrapPrivateKey(landowner.wrappedKey, PASSWORD);

  // Reject: signature over a DIFFERENT payload than the one prepared.
  const wrongPayloadSig = await signCanonicalString(loKey, prep1.data.payload + "TAMPERED");
  const wrongPayloadSubmit = await api("/transactions/submit", landowner.token, "POST", {
    nonce: prep1.data.nonce,
    signatureValue: wrongPayloadSig,
  });
  check(
    "REJECTED: signature over a different payload than prepared",
    wrongPayloadSubmit.status === 409 || wrongPayloadSubmit.status === 400,
    wrongPayloadSubmit.data,
  );

  // Reject: signature from the WRONG key (registrar's key signing landowner's payload).
  const registrarKey = await unwrapPrivateKey(registrar.wrappedKey, PASSWORD);
  const wrongKeySig = await signCanonicalString(registrarKey, prep1.data.payload);
  const wrongKeySubmit = await api("/transactions/submit", landowner.token, "POST", {
    nonce: prep1.data.nonce,
    signatureValue: wrongKeySig,
  });
  check(
    "REJECTED: signature produced by the wrong key",
    wrongKeySubmit.status === 409 || wrongKeySubmit.status === 400,
    wrongKeySubmit.data,
  );

  // Now the real, correct submit.
  const correctSig = await signCanonicalString(loKey, prep1.data.payload);
  const submit1 = await api("/transactions/submit", landowner.token, "POST", {
    nonce: prep1.data.nonce,
    signatureValue: correctSig,
  });
  check("transaction created with valid signature", submit1.status === 201, submit1.data);
  const transactionId = submit1.data?.id;

  // Reject: REPLAYED nonce — try to submit again with the same (now-used) nonce.
  const replaySubmit = await api("/transactions/submit", landowner.token, "POST", {
    nonce: prep1.data.nonce,
    signatureValue: correctSig,
  });
  check("REJECTED: replayed nonce", replaySubmit.status === 409, replaySubmit.data);

  // --- Expired nonce test: prepare a fresh one, backdate its expiresAt directly in the DB ---
  const lr2 = await api("/land-records", registrar.token, "POST", {
    surveyNumber: `SN-E2E-EXP-${stamp}`,
    location: "E2E Expiry Village",
    area: 1,
    currentOwnerId: landowner.id,
  });
  const formData2 = new FormData();
  formData2.append("file", new Blob([`%PDF-1.4\nexp ${stamp}`], { type: "application/pdf" }), "exp.pdf");
  const upload2Res = await fetch(`${BASE}/documents/upload`, {
    method: "POST",
    headers: { Authorization: `Bearer ${landowner.token}` },
    body: formData2,
  });
  const upload2Body = await upload2Res.json();
  const prepExp = await api("/transactions/prepare", landowner.token, "POST", {
    type: "REGISTRATION",
    landRecordId: lr2.data.id,
    documentPath: upload2Body.documentPath,
    documentHash: upload2Body.documentHash,
  });
  await prisma.signingNonce.update({
    where: { nonce: prepExp.data.nonce },
    data: { expiresAt: new Date(Date.now() - 1000) },
  });
  const expSig = await signCanonicalString(loKey, prepExp.data.payload);
  const expSubmit = await api("/transactions/submit", landowner.token, "POST", {
    nonce: prepExp.data.nonce,
    signatureValue: expSig,
  });
  check("REJECTED: expired nonce", expSubmit.status === 409, expSubmit.data);

  // --- Stage 2: VO prepare -> sign -> submit ---
  const voSubmit = await signAndSubmitTest(
    vo,
    `/transactions/${transactionId}/vo-review/prepare`,
    `/transactions/${transactionId}/vo-review/submit`,
  );
  check("VO approval signed and submitted", voSubmit.status === 200, voSubmit.data);

  // --- Stage 3: Registrar prepare -> sign -> submit ---
  const registrarSubmit = await signAndSubmitTest(
    registrar,
    `/transactions/${transactionId}/registrar-review/prepare`,
    `/transactions/${transactionId}/registrar-review/submit`,
  );
  check(
    "Registrar approval signed and submitted — transaction APPROVED",
    registrarSubmit.status === 200 && registrarSubmit.data?.status === "APPROVED",
    registrarSubmit.data,
  );

  // --- Final verify: every signer should show valid ---
  const verifyRes = await api(`/transactions/${transactionId}/verify`, registrar.token, "GET");
  check("verify status 200", verifyRes.status === 200);
  const allSignaturesValid = verifyRes.data?.signatureValidity?.every((s: { valid: boolean }) => s.valid);
  const allCertsValid = verifyRes.data?.signerIdentity?.every((s: { certificateValid: boolean }) => s.certificateValid);
  check("GET /transactions/:id/verify: all signatures valid", allSignaturesValid === true, verifyRes.data);
  check("GET /transactions/:id/verify: all certificates valid", allCertsValid === true);

  // --- Revoked certificate rejects signing ---
  const adminLoginRes = await fetch(`${BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
  });
  const adminLoginBody = await adminLoginRes.json();
  const adminToken = adminLoginBody.token;

  const voCertRes = await api(`/certificates/${vo.id}`, adminToken, "GET");
  const voCertId = voCertRes.data.id;
  const revokeRes = await api(`/certificates/${voCertId}/revoke`, adminToken, "POST", {
    reason: "E2E test revocation",
  });
  check("VO certificate revoked", revokeRes.status === 200, revokeRes.data);

  const lr3 = await api("/land-records", registrar.token, "POST", {
    surveyNumber: `SN-E2E-REVOKED-${stamp}`,
    location: "E2E Revoked Village",
    area: 1,
    currentOwnerId: landowner.id,
  });
  const formData3 = new FormData();
  formData3.append("file", new Blob([`%PDF-1.4\nrev ${stamp}`], { type: "application/pdf" }), "rev.pdf");
  const upload3Res = await fetch(`${BASE}/documents/upload`, {
    method: "POST",
    headers: { Authorization: `Bearer ${landowner.token}` },
    body: formData3,
  });
  const upload3Body = await upload3Res.json();
  const prep3 = await api("/transactions/prepare", landowner.token, "POST", {
    type: "REGISTRATION",
    landRecordId: lr3.data.id,
    documentPath: upload3Body.documentPath,
    documentHash: upload3Body.documentHash,
  });
  const sig3 = await signCanonicalString(loKey, prep3.data.payload);
  const submit3 = await api("/transactions/submit", landowner.token, "POST", {
    nonce: prep3.data.nonce,
    signatureValue: sig3,
  });
  const txn3Id = submit3.data.id;

  // VO (now revoked) tries to prepare a review — should be rejected before any signing.
  const voPrepareAfterRevoke = await api(`/transactions/${txn3Id}/vo-review/prepare`, vo.token, "POST");
  check(
    "REJECTED: revoked certificate cannot prepare a signature",
    voPrepareAfterRevoke.status === 403,
    voPrepareAfterRevoke.data,
  );

  console.log(`\n${failures === 0 ? "ALL PASSED" : `${failures} FAILED`}`);
  await prisma.$disconnect();
  if (failures > 0) process.exit(1);
}

main().catch(async (err) => {
  console.error(err);
  await prisma.$disconnect();
  process.exit(1);
});
