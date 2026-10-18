// scripts/test-transfer-ownership.ts
//
// Full integration test against a RUNNING server (node server.ts on
// localhost:4000), exercising the real HTTP API with real client-side
// crypto (frontend/src/lib/clientCrypto.ts, no mocks) — same pattern as
// scripts/test-client-signing-e2e.ts. Proves the ownership-transfer
// guarantees end to end:
//   1. A normal transfer (both stages approved) changes the land record's
//      currentOwnerId to the buyer.
//   2. A transfer rejected at either stage does NOT change the owner, and
//      the record becomes transferable again immediately.
//   3. A second transfer cannot be started while one is already pending
//      (double-sale protection).
//   4. Someone who isn't the current owner cannot start a transfer.
// Also covers the two new buyer-validity checks added alongside this:
// buyer must be a registered Landowner, and buyer cannot be the seller.
//
// Run with: node scripts/test-transfer-ownership.ts
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

  return { id: registerBody.id, email, token: loginBody.token, wrappedKey: loginBody.wrappedKey };
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
    location: "Transfer Test Village",
    area: 1,
    currentOwnerId: ownerId,
  });
  if (res.status !== 201) throw new Error(`Land record creation failed: ${JSON.stringify(res.data)}`);
  return res.data.id as string;
}

async function startTransfer(
  seller: RegisteredUser,
  landRecordId: string,
  toOwnerId: string,
  label: string,
): Promise<{ status: number; data: any }> {
  const upload = await uploadTestDocument(seller.token, label);
  const prepared = await api("/transactions/prepare", seller.token, "POST", {
    type: "TRANSFER",
    landRecordId,
    toOwnerId,
    documentPath: upload.documentPath,
    documentHash: upload.documentHash,
  });
  if (prepared.status !== 200) return prepared;
  const privateKey = await unwrapPrivateKey(seller.wrappedKey, PASSWORD);
  const signatureValue = await signCanonicalString(privateKey, prepared.data.payload);
  return api("/transactions/submit", seller.token, "POST", { nonce: prepared.data.nonce, signatureValue });
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
  const seller = await registerClientSideUser("Transfer Seller", `transfer-seller-${stamp}@example.com`, "LANDOWNER");
  const buyer = await registerClientSideUser("Transfer Buyer", `transfer-buyer-${stamp}@example.com`, "LANDOWNER");
  const outsider = await registerClientSideUser("Transfer Outsider", `transfer-outsider-${stamp}@example.com`, "LANDOWNER");
  const vo = await registerClientSideUser("Transfer VO", `transfer-vo-${stamp}@example.com`, "VILLAGE_OFFICER");
  const registrar = await registerClientSideUser("Transfer Registrar", `transfer-registrar-${stamp}@example.com`, "REGISTRAR");
  console.log("Registered 5 client-side-keyed users.\n");

  // --- Guarantee 4: a non-owner cannot start a transfer ---
  const lrNonOwner = await createLandRecord(registrar.token, seller.id, `SN-XFER-NONOWNER-${stamp}`);
  const nonOwnerAttempt = await startTransfer(outsider, lrNonOwner, buyer.id, "nonowner");
  check(
    "non-owner cannot start a transfer on someone else's record",
    nonOwnerAttempt.status === 403,
    nonOwnerAttempt.data,
  );

  // --- Extra coverage: buyer must be a registered Landowner, buyer != seller ---
  const lrBuyerChecks = await createLandRecord(registrar.token, seller.id, `SN-XFER-BUYERCHECK-${stamp}`);
  const selfTransfer = await startTransfer(seller, lrBuyerChecks, seller.id, "self");
  check("seller cannot transfer a record to themselves", selfTransfer.status === 400, selfTransfer.data);
  const nonLandownerBuyer = await startTransfer(seller, lrBuyerChecks, vo.id, "nonlandowner");
  check("buyer must be a registered Landowner (VO rejected)", nonLandownerBuyer.status === 400, nonLandownerBuyer.data);

  // --- Guarantee 1: a normal, fully-approved transfer changes the owner ---
  const lrNormal = await createLandRecord(registrar.token, seller.id, `SN-XFER-NORMAL-${stamp}`);
  const normalCreate = await startTransfer(seller, lrNormal, buyer.id, "normal");
  check("transfer created", normalCreate.status === 201, normalCreate.data);
  const normalTxnId = normalCreate.data?.id;

  const normalVo = await approveStage(vo, normalTxnId, "vo-review");
  check("VO approved the transfer", normalVo.status === 200 && normalVo.data?.status === "PENDING_REGISTRAR", normalVo.data);
  const normalRegistrar = await approveStage(registrar, normalTxnId, "registrar-review");
  check(
    "Registrar approved the transfer — status APPROVED",
    normalRegistrar.status === 200 && normalRegistrar.data?.status === "APPROVED",
    normalRegistrar.data,
  );
  const normalRecordAfter = await prisma.landRecord.findUnique({ where: { id: lrNormal } });
  check(
    "land record's currentOwnerId is now the buyer",
    normalRecordAfter?.currentOwnerId === buyer.id,
    normalRecordAfter,
  );
  check("land record status back to ACTIVE after approval", normalRecordAfter?.status === "ACTIVE");

  // --- Guarantee 2: a transfer rejected at the VO stage does not change the owner ---
  const lrRejectVo = await createLandRecord(registrar.token, seller.id, `SN-XFER-REJVO-${stamp}`);
  const rejectVoCreate = await startTransfer(seller, lrRejectVo, buyer.id, "reject-vo");
  const rejectVoTxnId = rejectVoCreate.data?.id;
  const voReject = await rejectStage(vo, rejectVoTxnId, "vo-review");
  check("VO rejected the transfer", voReject.status === 200 && voReject.data?.status === "REJECTED", voReject.data);
  const rejectVoRecordAfter = await prisma.landRecord.findUnique({ where: { id: lrRejectVo } });
  check("owner unchanged after VO rejection", rejectVoRecordAfter?.currentOwnerId === seller.id, rejectVoRecordAfter);
  check("record is ACTIVE (transferable again) after VO rejection", rejectVoRecordAfter?.status === "ACTIVE");

  // Prove "transferable again" isn't just a status flag — a fresh transfer
  // on the same record actually succeeds now.
  const retryAfterVoReject = await startTransfer(seller, lrRejectVo, buyer.id, "retry-after-vo-reject");
  check("a new transfer can be started after a VO rejection", retryAfterVoReject.status === 201, retryAfterVoReject.data);

  // --- Guarantee 2 (continued): rejected at the Registrar stage ---
  const lrRejectRegistrar = await createLandRecord(registrar.token, seller.id, `SN-XFER-REJREG-${stamp}`);
  const rejectRegCreate = await startTransfer(seller, lrRejectRegistrar, buyer.id, "reject-registrar");
  const rejectRegTxnId = rejectRegCreate.data?.id;
  await approveStage(vo, rejectRegTxnId, "vo-review");
  const registrarReject = await rejectStage(registrar, rejectRegTxnId, "registrar-review");
  check(
    "Registrar rejected the transfer",
    registrarReject.status === 200 && registrarReject.data?.status === "REJECTED",
    registrarReject.data,
  );
  const rejectRegRecordAfter = await prisma.landRecord.findUnique({ where: { id: lrRejectRegistrar } });
  check(
    "owner unchanged after Registrar rejection",
    rejectRegRecordAfter?.currentOwnerId === seller.id,
    rejectRegRecordAfter,
  );
  check("record is ACTIVE (transferable again) after Registrar rejection", rejectRegRecordAfter?.status === "ACTIVE");

  // --- Guarantee 3: a second pending transfer is blocked (double-sale protection) ---
  const lrDoubleSale = await createLandRecord(registrar.token, seller.id, `SN-XFER-DOUBLESALE-${stamp}`);
  const firstPending = await startTransfer(seller, lrDoubleSale, buyer.id, "double-sale-first");
  check("first transfer created and left pending", firstPending.status === 201, firstPending.data);
  const secondPending = await startTransfer(seller, lrDoubleSale, outsider.id, "double-sale-second");
  check(
    "a second transfer is blocked while one is already pending",
    secondPending.status === 409,
    secondPending.data,
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
