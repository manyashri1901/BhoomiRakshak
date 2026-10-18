// scripts/test-succession.ts
//
// Full integration test against a RUNNING server (node server.ts on
// localhost:4000), exercising the real HTTP API with real client-side
// crypto (frontend/src/lib/clientCrypto.ts, no mocks) — same pattern as
// scripts/test-client-signing-e2e.ts and scripts/test-transfer-ownership.ts.
// Proves the SUCCESSION (owner-deceased) guarantees end to end:
//   1. Succession changes the owner and revokes the dead owner's certificate.
//   2. The dead owner can no longer log in, sign, or start a transaction.
//   3. Their signatures made WHILE ALIVE still verify as valid-at-signing-
//      time, even though their certificate is now revoked.
//   4. A signature forged with the revoked key after death — inserted
//      directly into the database with a BACKDATED signedAt, bypassing the
//      real API entirely — is rejected: the as-of-time check trusts only
//      the hash-chained audit log's own timestamp, never the Signature
//      row's own (tamperable) signedAt column.
//   5. A succession claim without a death certificate is rejected.
//   6. Rejection leaves the owner unchanged.
//   7. A second pending succession/transfer on the same record is blocked.
//
// Run with: node scripts/test-succession.ts
// (server must already be running: npm run dev)

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

  const loginRes = await fetch(`${BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: PASSWORD }),
  });
  const loginBody = await loginRes.json();
  if (loginRes.status !== 200) throw new Error(`Login failed for ${email}: ${JSON.stringify(loginBody)}`);

  return { id: registerBody.id, email, token: loginBody.token, wrappedKey: loginBody.wrappedKey, keyPair };
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

async function uploadTestDocument(token: string, label: string): Promise<{ documentPath: string; documentHash: string }> {
  const formData = new FormData();
  formData.append("file", new Blob([`%PDF-1.4\n${label}`], { type: "application/pdf" }), `${label}.pdf`);
  const res = await fetch(`${BASE}/documents/upload`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: formData,
  });
  const body = await res.json();
  if (res.status !== 201) throw new Error(`Upload failed: ${JSON.stringify(body)}`);
  return body;
}

async function createLandRecord(registrarToken: string, ownerId: string, surveyNumber: string) {
  const res = await api("/land-records", registrarToken, "POST", {
    surveyNumber,
    location: "Succession Test Village",
    area: 1,
    currentOwnerId: ownerId,
  });
  if (res.status !== 201) throw new Error(`Land record creation failed: ${JSON.stringify(res.data)}`);
  return res.data.id as string;
}

async function prepareAndSubmitCreate(
  actor: RegisteredUser,
  input: Record<string, unknown>,
): Promise<{ status: number; data: any }> {
  const prepared = await api("/transactions/prepare", actor.token, "POST", input);
  if (prepared.status !== 200) return prepared;
  const privateKey = await unwrapPrivateKey(actor.wrappedKey, PASSWORD);
  const signatureValue = await signCanonicalString(privateKey, prepared.data.payload);
  return api("/transactions/submit", actor.token, "POST", { nonce: prepared.data.nonce, signatureValue });
}

async function approveStage(
  actor: RegisteredUser,
  transactionId: string,
  stage: "vo-review" | "registrar-review",
): Promise<{ status: number; data: any }> {
  const prepared = await api(`/transactions/${transactionId}/${stage}/prepare`, actor.token, "POST");
  if (prepared.status !== 200) return prepared;
  const privateKey = await unwrapPrivateKey(actor.wrappedKey, PASSWORD);
  const signatureValue = await signCanonicalString(privateKey, prepared.data.payload);
  return api(`/transactions/${transactionId}/${stage}/submit`, actor.token, "POST", {
    nonce: prepared.data.nonce,
    signatureValue,
  });
}

async function rejectStage(
  actor: RegisteredUser,
  transactionId: string,
  stage: "vo-review" | "registrar-review",
): Promise<{ status: number; data: any }> {
  return api(`/transactions/${transactionId}/${stage}/reject`, actor.token, "POST", { reason: "Test rejection" });
}

async function main() {
  const stamp = Date.now();
  const deceased = await registerClientSideUser("Succession Deceased", `succ-deceased-${stamp}@example.com`, "LANDOWNER");
  const heir = await registerClientSideUser("Succession Heir", `succ-heir-${stamp}@example.com`, "LANDOWNER");
  const vo = await registerClientSideUser("Succession VO", `succ-vo-${stamp}@example.com`, "VILLAGE_OFFICER");
  const registrar = await registerClientSideUser("Succession Registrar", `succ-registrar-${stamp}@example.com`, "REGISTRAR");
  console.log("Registered 4 client-side-keyed users.\n");

  // --- Setup: deceased's land record, with ONE legitimate self-signed
  // transaction (REGISTRATION) made WHILE THEY WERE STILL ALIVE — this is
  // the signature we'll later re-verify after revocation. ---
  const lrMain = await createLandRecord(registrar.token, deceased.id, `SN-SUCC-MAIN-${stamp}`);
  const regUpload = await uploadTestDocument(deceased.token, "pre-death-registration");
  const regCreate = await prepareAndSubmitCreate(deceased, {
    type: "REGISTRATION",
    landRecordId: lrMain,
    documentPath: regUpload.documentPath,
    documentHash: regUpload.documentHash,
  });
  check("deceased's pre-death REGISTRATION transaction created", regCreate.status === 201, regCreate.data);
  const preDeathTxnId = regCreate.data?.id;
  await approveStage(vo, preDeathTxnId, "vo-review");
  const regRegistrar = await approveStage(registrar, preDeathTxnId, "registrar-review");
  check("pre-death transaction fully approved (while deceased was still alive)", regRegistrar.status === 200 && regRegistrar.data?.status === "APPROVED", regRegistrar.data);

  // --- Guarantee 5: a succession claim without a death certificate is rejected ---
  const noDeathCertAttempt = await api("/transactions/prepare", heir.token, "POST", {
    type: "SUCCESSION",
    landRecordId: lrMain,
  });
  check("succession claim without a death certificate is rejected", noDeathCertAttempt.status === 400, noDeathCertAttempt.data);

  // --- Guarantee 6: rejection leaves the owner unchanged (separate record, so lrMain's own flow below is unaffected) ---
  const lrReject = await createLandRecord(registrar.token, deceased.id, `SN-SUCC-REJECT-${stamp}`);
  const rejectDeathCert = await uploadTestDocument(heir.token, "death-cert-for-rejected-claim");
  const rejectClaim = await prepareAndSubmitCreate(heir, {
    type: "SUCCESSION",
    landRecordId: lrReject,
    documentPath: rejectDeathCert.documentPath,
    documentHash: rejectDeathCert.documentHash,
  });
  check("succession claim created (to be rejected)", rejectClaim.status === 201, rejectClaim.data);
  const voReject = await rejectStage(vo, rejectClaim.data?.id, "vo-review");
  check("VO rejected the succession claim", voReject.status === 200 && voReject.data?.status === "REJECTED", voReject.data);
  const lrRejectAfter = await prisma.landRecord.findUnique({ where: { id: lrReject } });
  check("owner unchanged after a rejected succession claim", lrRejectAfter?.currentOwnerId === deceased.id, lrRejectAfter);
  check("record is ACTIVE (transferable/claimable again) after rejection", lrRejectAfter?.status === "ACTIVE");
  const deceasedStillActiveAfterRejection = await prisma.user.findUnique({ where: { id: deceased.id } });
  check("deceased's own account status is unaffected by a rejected claim", deceasedStillActiveAfterRejection?.status === "ACTIVE");

  // --- Guarantee 1: the real succession on lrMain — changes the owner and revokes the certificate ---
  const deathCert = await uploadTestDocument(heir.token, "death-certificate");
  const heirDoc = await uploadTestDocument(heir.token, "legal-heir-certificate");
  const claimCreate = await prepareAndSubmitCreate(heir, {
    type: "SUCCESSION",
    landRecordId: lrMain,
    documentPath: deathCert.documentPath,
    documentHash: deathCert.documentHash,
    secondaryDocumentPath: heirDoc.documentPath,
    secondaryDocumentHash: heirDoc.documentHash,
  });
  check("succession claim created with death certificate + heir document", claimCreate.status === 201, claimCreate.data);
  const successionTxnId = claimCreate.data?.id;

  // --- Guarantee 7 (first half): a second pending succession/transfer on the same record is blocked ---
  const secondClaimAttempt = await api("/transactions/prepare", heir.token, "POST", {
    type: "SUCCESSION",
    landRecordId: lrMain,
    documentPath: deathCert.documentPath,
    documentHash: deathCert.documentHash,
  });
  check("a second pending claim on the same record is blocked", secondClaimAttempt.status === 409, secondClaimAttempt.data);

  const voApprove = await approveStage(vo, successionTxnId, "vo-review");
  check("VO approved the succession claim", voApprove.status === 200 && voApprove.data?.status === "PENDING_REGISTRAR", voApprove.data);
  const registrarApprove = await approveStage(registrar, successionTxnId, "registrar-review");
  check("Registrar approved the succession claim — status APPROVED", registrarApprove.status === 200 && registrarApprove.data?.status === "APPROVED", registrarApprove.data);

  const lrMainAfter = await prisma.landRecord.findUnique({ where: { id: lrMain } });
  check("land record's currentOwnerId is now the heir", lrMainAfter?.currentOwnerId === heir.id, lrMainAfter);

  const deceasedAfter = await prisma.user.findUnique({ where: { id: deceased.id } });
  check("deceased's account status is now DECEASED", deceasedAfter?.status === "DECEASED");

  const deceasedCertAfter = await prisma.certificate.findUnique({ where: { subjectUserId: deceased.id } });
  check("deceased's certificate is revoked", deceasedCertAfter?.revoked === true, deceasedCertAfter);
  check(
    'deceased\'s certificate revokedReason is "Owner deceased"',
    deceasedCertAfter?.revokedReason === "Owner deceased",
    deceasedCertAfter?.revokedReason,
  );

  // --- Guarantee 2: the dead owner can no longer log in, sign, or start a transaction ---
  const loginAfterDeath = await fetch(`${BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: deceased.email, password: PASSWORD }),
  });
  check("deceased cannot log in", loginAfterDeath.status === 403, await loginAfterDeath.json());

  // Their OLD token (issued before death, still unexpired) must also now
  // be rejected the moment it's used for anything requiring a trustworthy
  // certificate — requireCertifiedRole checks the certificate live, not a
  // cached session claim.
  const startTxnAfterDeath = await api("/transactions/prepare", deceased.token, "POST", {
    type: "UPDATE",
    landRecordId: lrMain,
    documentPath: deathCert.documentPath,
    documentHash: deathCert.documentHash,
  });
  check(
    "deceased's still-unexpired token can no longer start a transaction (CERT_REVOKED)",
    startTxnAfterDeath.status === 403 && startTxnAfterDeath.data?.reason === "CERT_REVOKED",
    startTxnAfterDeath.data,
  );

  // --- Guarantee 3: deceased's signature made WHILE ALIVE still verifies
  // as valid-at-signing-time, even though the certificate is now revoked ---
  const verifyPreDeath = await api(`/transactions/${preDeathTxnId}/verify`, registrar.token, "GET");
  check("verify endpoint reachable for the pre-death transaction", verifyPreDeath.status === 200, verifyPreDeath.data);
  const deceasedSignerEntry = verifyPreDeath.data?.signerIdentity?.find((s: any) => s.role === "LANDOWNER");
  check(
    "deceased's pre-death signature is still reported certificateValid (valid AT SIGNING TIME)",
    deceasedSignerEntry?.certificateValid === true,
    deceasedSignerEntry,
  );
  check(
    "but currentlyRevoked is true (the certificate IS revoked now)",
    deceasedSignerEntry?.currentlyRevoked === true,
    deceasedSignerEntry,
  );

  // --- Guarantee 4: a signature forged with the revoked key after death
  // (inserted directly into the database, bypassing the real API, with a
  // BACKDATED signedAt claiming it happened before revocation) is
  // rejected — because the as-of-time check trusts only the hash-chained
  // audit log, never this tamperable column. ---
  const lrForge = await createLandRecord(registrar.token, heir.id, `SN-SUCC-FORGE-${stamp}`);
  // A legitimate-looking transaction row, created directly (no real
  // prepare/submit round trip) so there is deliberately NO audit log
  // entry backing it.
  const forgedTxn = await prisma.transaction.create({
    data: {
      type: "UPDATE",
      landRecordId: lrForge,
      fromOwnerId: null,
      toOwnerId: heir.id,
      documentPath: regUpload.documentPath,
      documentHash: regUpload.documentHash,
      status: "APPROVED",
    },
  });
  // The forged signature itself: genuinely signed with the deceased's
  // REAL private key (simulating a compromised key used after death —
  // the cryptographic signature is authentic), but its signedAt is
  // BACKDATED to a moment before the real revocation, attempting to
  // disguise it as having happened while the certificate was still valid.
  const deceasedPrivateKey = await unwrapPrivateKey(deceased.wrappedKey, PASSWORD);
  const forgedPayload = canonicalStringify({
    type: "UPDATE",
    landRecordId: lrForge,
    fromOwnerId: null,
    toOwnerId: heir.id,
    documentPath: regUpload.documentPath,
    documentHash: regUpload.documentHash,
    secondaryDocumentPath: null,
    secondaryDocumentHash: null,
    actorId: deceased.id,
    certificateFingerprint: deceasedCertAfter!.fingerprint,
    createdAt: forgedTxn.createdAt.toISOString(),
  });
  const forgedSignatureValue = await signCanonicalString(deceasedPrivateKey, forgedPayload);
  const backdatedSignedAt = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000); // one year ago — well before revocation
  await prisma.signature.create({
    data: {
      transactionId: forgedTxn.id,
      actorId: deceased.id,
      role: "LANDOWNER",
      signatureValue: forgedSignatureValue,
      dataHash: "0".repeat(64),
      signedAt: backdatedSignedAt,
    },
  });

  const verifyForged = await api(`/transactions/${forgedTxn.id}/verify`, registrar.token, "GET");
  const forgedSignerEntry = verifyForged.data?.signerIdentity?.find((s: any) => s.role === "LANDOWNER");
  check(
    "forged signature's claimed (backdated) signedAt is NOT trusted — no matching audit log entry",
    forgedSignerEntry?.signingTimeTrusted === false,
    forgedSignerEntry,
  );
  check(
    "forged signature is therefore reported certificateValid: false, despite the backdated timestamp claiming it predates revocation",
    forgedSignerEntry?.certificateValid === false,
    forgedSignerEntry,
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
