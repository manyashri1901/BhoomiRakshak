// scripts/load-test.ts
//
// Load test against a RUNNING server (node server.ts on localhost:4000),
// using real client-side crypto (frontend/src/lib/clientCrypto.ts, no
// mocks) for every signature — same conventions as
// scripts/test-client-signing-e2e.ts, scripts/test-transfer-ownership.ts,
// and scripts/test-succession.ts. Spins up ~50 users (a realistic mix of
// roles), runs a batch of normal REGISTRATION/TRANSFER activity under
// concurrency, and — per this project's succession feature — 5 of the
// Landowners are deceased owners with a designated heir, each going
// through a full SUCCESSION claim (death certificate, VO + Registrar
// review, final approval). Writes a results table to
// docs/load-test-results.md (same convention as scripts/attack-simulation.ts
// writing docs/attack-results.md) and prints a summary to the console.
//
// PREREQUISITE: registration is rate-limited to RATE_LIMIT_REGISTER_MAX
// (default 20) per hour, PER IP — not per email. ~50 registrations in one
// run from one machine WILL exceed that default. Before running this
// script, temporarily raise it in .env, e.g.:
//   RATE_LIMIT_REGISTER_MAX=200
// and restart the dev server. Safe to revert afterward.
//
// Run with: node scripts/load-test.ts
// (server must already be running: npm run dev)

import "dotenv/config";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  generateKeyPair,
  exportPublicKeySpkiPem,
  fingerprintOfPem,
  wrapPrivateKey,
  unwrapPrivateKey,
  signCanonicalString,
} from "../frontend/src/lib/clientCrypto.ts";
import { canonicalStringify } from "../frontend/src/lib/canonicalize.ts";

const BASE = "http://localhost:4000/api";
const PASSWORD = "testpass123!";

const LANDOWNER_COUNT = 42;
const VO_COUNT = 4;
const REGISTRAR_COUNT = 4;
const SUCCESSION_PAIR_COUNT = 5; // 5 deceased owners, each with 1 heir
const TRANSFER_PAIR_COUNT = 10; // additional ownership transfers among the remaining landowners
const CONCURRENCY = 6;

interface RegisteredUser {
  id: string;
  email: string;
  name: string;
  token: string;
  wrappedKey: { ciphertext: string; salt: string; iv: string };
}

interface StepResult {
  category: string;
  ok: boolean;
  detail?: string;
}

const results: StepResult[] = [];
function record(category: string, ok: boolean, detail?: string) {
  results.push({ category, ok, detail });
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
    throw new Error(`Registration failed for ${email} (status ${registerRes.status}): ${JSON.stringify(registerBody)}`);
  }

  const loginRes = await fetch(`${BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: PASSWORD }),
  });
  const loginBody = await loginRes.json();
  if (loginRes.status !== 200) throw new Error(`Login failed for ${email}: ${JSON.stringify(loginBody)}`);

  return { id: registerBody.id, email, name, token: loginBody.token, wrappedKey: loginBody.wrappedKey };
}

async function uploadTestDocument(token: string, label: string): Promise<{ documentPath: string; documentHash: string }> {
  const formData = new FormData();
  formData.append("file", new Blob([`%PDF-1.4\n${label}-${Math.random()}`], { type: "application/pdf" }), `${label}.pdf`);
  const res = await fetch(`${BASE}/documents/upload`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: formData,
  });
  const body = await res.json();
  if (res.status !== 201) throw new Error(`Upload failed: ${JSON.stringify(body)}`);
  return body;
}

async function createLandRecord(registrarToken: string, ownerId: string, surveyNumber: string): Promise<string> {
  const res = await api("/land-records", registrarToken, "POST", {
    surveyNumber,
    location: "Load Test Village",
    area: 1,
    currentOwnerId: ownerId,
  });
  if (res.status !== 201) throw new Error(`Land record creation failed: ${JSON.stringify(res.data)}`);
  return res.data.id as string;
}

async function prepareAndSubmitCreate(actor: RegisteredUser, input: Record<string, unknown>) {
  const prepared = await api("/transactions/prepare", actor.token, "POST", input);
  if (prepared.status !== 200) return prepared;
  const privateKey = await unwrapPrivateKey(actor.wrappedKey, PASSWORD);
  const signatureValue = await signCanonicalString(privateKey, prepared.data.payload);
  return api("/transactions/submit", actor.token, "POST", { nonce: prepared.data.nonce, signatureValue });
}

async function approveStage(actor: RegisteredUser, transactionId: string, stage: "vo-review" | "registrar-review") {
  const prepared = await api(`/transactions/${transactionId}/${stage}/prepare`, actor.token, "POST");
  if (prepared.status !== 200) return prepared;
  const privateKey = await unwrapPrivateKey(actor.wrappedKey, PASSWORD);
  const signatureValue = await signCanonicalString(privateKey, prepared.data.payload);
  return api(`/transactions/${transactionId}/${stage}/submit`, actor.token, "POST", {
    nonce: prepared.data.nonce,
    signatureValue,
  });
}

// Simple bounded-concurrency mapper — every row is independent (its own
// land record/transaction), so running CONCURRENCY at a time is safe.
async function mapWithConcurrency<T, R>(items: T[], concurrency: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return out;
}

function pick<T>(arr: T[], index: number): T {
  return arr[index % arr.length];
}

async function main() {
  const stamp = Date.now();
  const overallStart = Date.now();

  console.log(`Registering ${LANDOWNER_COUNT + VO_COUNT + REGISTRAR_COUNT} users...`);
  const regStart = Date.now();

  const landowners: RegisteredUser[] = [];
  for (let i = 0; i < LANDOWNER_COUNT; i++) {
    landowners.push(await registerClientSideUser(`Load Landowner ${i}`, `load-lo-${stamp}-${i}@example.com`, "LANDOWNER"));
  }
  const vos: RegisteredUser[] = [];
  for (let i = 0; i < VO_COUNT; i++) {
    vos.push(await registerClientSideUser(`Load VO ${i}`, `load-vo-${stamp}-${i}@example.com`, "VILLAGE_OFFICER"));
  }
  const registrars: RegisteredUser[] = [];
  for (let i = 0; i < REGISTRAR_COUNT; i++) {
    registrars.push(await registerClientSideUser(`Load Registrar ${i}`, `load-reg-${stamp}-${i}@example.com`, "REGISTRAR"));
  }
  const totalUsers = landowners.length + vos.length + registrars.length;
  const regElapsedMs = Date.now() - regStart;
  record("User registration", true, `${totalUsers} users in ${regElapsedMs}ms`);
  console.log(`Registered ${totalUsers} users in ${regElapsedMs}ms.\n`);

  // Reserve the first 2*SUCCESSION_PAIR_COUNT landowners as deceased/heir
  // pairs, the next 2*TRANSFER_PAIR_COUNT as transfer pairs, and the rest
  // for plain REGISTRATION activity.
  const successionPairs = Array.from({ length: SUCCESSION_PAIR_COUNT }, (_, i) => ({
    deceased: landowners[i * 2],
    heir: landowners[i * 2 + 1],
  }));
  const afterSuccession = landowners.slice(SUCCESSION_PAIR_COUNT * 2);
  const transferPairs = Array.from({ length: TRANSFER_PAIR_COUNT }, (_, i) => ({
    seller: afterSuccession[i * 2],
    buyer: afterSuccession[i * 2 + 1],
  }));
  const plainLandowners = afterSuccession.slice(TRANSFER_PAIR_COUNT * 2);

  // --- Plain REGISTRATION activity ---
  console.log(`Running ${plainLandowners.length} REGISTRATION transactions (concurrency ${CONCURRENCY})...`);
  const registrationStart = Date.now();
  await mapWithConcurrency(plainLandowners, CONCURRENCY, async (owner, i) => {
    try {
      const vo = pick(vos, i);
      const registrar = pick(registrars, i);
      const lr = await createLandRecord(registrar.token, owner.id, `SN-LOAD-REG-${stamp}-${i}`);
      const upload = await uploadTestDocument(owner.token, `reg-${i}`);
      const created = await prepareAndSubmitCreate(owner, {
        type: "REGISTRATION",
        landRecordId: lr,
        documentPath: upload.documentPath,
        documentHash: upload.documentHash,
      });
      if (created.status !== 201) throw new Error(`create failed: ${JSON.stringify(created.data)}`);
      const voResult = await approveStage(vo, created.data.id, "vo-review");
      if (voResult.status !== 200) throw new Error(`VO approve failed: ${JSON.stringify(voResult.data)}`);
      const registrarResult = await approveStage(registrar, created.data.id, "registrar-review");
      if (registrarResult.status !== 200 || registrarResult.data?.status !== "APPROVED") {
        throw new Error(`Registrar approve failed: ${JSON.stringify(registrarResult.data)}`);
      }
      record("REGISTRATION transaction", true);
    } catch (err) {
      record("REGISTRATION transaction", false, String(err));
    }
  });
  const registrationElapsedMs = Date.now() - registrationStart;
  console.log(`REGISTRATION batch done in ${registrationElapsedMs}ms.\n`);

  // --- TRANSFER activity between pairs ---
  console.log(`Running ${transferPairs.length} TRANSFER transactions (concurrency ${CONCURRENCY})...`);
  const transferStart = Date.now();
  await mapWithConcurrency(transferPairs, CONCURRENCY, async ({ seller, buyer }, i) => {
    try {
      const vo = pick(vos, i);
      const registrar = pick(registrars, i);
      const lr = await createLandRecord(registrar.token, seller.id, `SN-LOAD-XFER-${stamp}-${i}`);
      const upload = await uploadTestDocument(seller.token, `xfer-${i}`);
      const created = await prepareAndSubmitCreate(seller, {
        type: "TRANSFER",
        landRecordId: lr,
        toOwnerId: buyer.id,
        documentPath: upload.documentPath,
        documentHash: upload.documentHash,
      });
      if (created.status !== 201) throw new Error(`create failed: ${JSON.stringify(created.data)}`);
      const voResult = await approveStage(vo, created.data.id, "vo-review");
      if (voResult.status !== 200) throw new Error(`VO approve failed: ${JSON.stringify(voResult.data)}`);
      const registrarResult = await approveStage(registrar, created.data.id, "registrar-review");
      if (registrarResult.status !== 200 || registrarResult.data?.status !== "APPROVED") {
        throw new Error(`Registrar approve failed: ${JSON.stringify(registrarResult.data)}`);
      }
      record("TRANSFER transaction", true);
    } catch (err) {
      record("TRANSFER transaction", false, String(err));
    }
  });
  const transferElapsedMs = Date.now() - transferStart;
  console.log(`TRANSFER batch done in ${transferElapsedMs}ms.\n`);

  // --- SUCCESSION scenario: 5 deceased owners, each with an heir ---
  console.log(`Running ${successionPairs.length} SUCCESSION claims (concurrency ${CONCURRENCY})...`);
  const successionStart = Date.now();
  await mapWithConcurrency(successionPairs, CONCURRENCY, async ({ deceased, heir }, i) => {
    try {
      const vo = pick(vos, i);
      const registrar = pick(registrars, i);
      const lr = await createLandRecord(registrar.token, deceased.id, `SN-LOAD-SUCC-${stamp}-${i}`);

      // Pre-death activity: the deceased signs a REGISTRATION on their own
      // record while still alive — this is the signature load-test checks
      // remains valid-at-signing-time after death below.
      const regUpload = await uploadTestDocument(deceased.token, `succ-predeath-${i}`);
      const regCreated = await prepareAndSubmitCreate(deceased, {
        type: "REGISTRATION",
        landRecordId: lr,
        documentPath: regUpload.documentPath,
        documentHash: regUpload.documentHash,
      });
      if (regCreated.status !== 201) throw new Error(`pre-death registration failed: ${JSON.stringify(regCreated.data)}`);
      await approveStage(vo, regCreated.data.id, "vo-review");
      const regApproved = await approveStage(registrar, regCreated.data.id, "registrar-review");
      if (regApproved.status !== 200 || regApproved.data?.status !== "APPROVED") {
        throw new Error(`pre-death registration approval failed: ${JSON.stringify(regApproved.data)}`);
      }

      // The heir's claim.
      const deathCert = await uploadTestDocument(heir.token, `death-cert-${i}`);
      const claimCreated = await prepareAndSubmitCreate(heir, {
        type: "SUCCESSION",
        landRecordId: lr,
        documentPath: deathCert.documentPath,
        documentHash: deathCert.documentHash,
      });
      if (claimCreated.status !== 201) throw new Error(`succession claim failed: ${JSON.stringify(claimCreated.data)}`);
      const voResult = await approveStage(vo, claimCreated.data.id, "vo-review");
      if (voResult.status !== 200) throw new Error(`VO approve failed: ${JSON.stringify(voResult.data)}`);
      const registrarResult = await approveStage(registrar, claimCreated.data.id, "registrar-review");
      if (registrarResult.status !== 200 || registrarResult.data?.status !== "APPROVED") {
        throw new Error(`Registrar approve failed: ${JSON.stringify(registrarResult.data)}`);
      }

      // Verify the cascade: owner changed, deceased can't log in anymore,
      // and their pre-death signature still verifies as valid-at-signing-time.
      const lrAfter = await api(`/land-records/${lr}/history`, heir.token, "GET");
      if (lrAfter.data?.landRecord?.currentOwnerId !== heir.id) {
        throw new Error(`owner did not change to heir: ${JSON.stringify(lrAfter.data?.landRecord)}`);
      }
      const loginAfterDeath = await fetch(`${BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: deceased.email, password: PASSWORD }),
      });
      if (loginAfterDeath.status !== 403) {
        throw new Error(`deceased could still log in: status ${loginAfterDeath.status}`);
      }
      const verifyPreDeath = await api(`/transactions/${regCreated.data.id}/verify`, registrar.token, "GET");
      const deceasedSigner = verifyPreDeath.data?.signerIdentity?.find((s: any) => s.role === "LANDOWNER");
      if (deceasedSigner?.certificateValid !== true) {
        throw new Error(`pre-death signature no longer valid-at-signing-time: ${JSON.stringify(deceasedSigner)}`);
      }

      record("SUCCESSION claim", true);
    } catch (err) {
      record("SUCCESSION claim", false, String(err));
    }
  });
  const successionElapsedMs = Date.now() - successionStart;
  console.log(`SUCCESSION batch done in ${successionElapsedMs}ms.\n`);

  const overallElapsedMs = Date.now() - overallStart;

  // --- Summary + results table ---
  const categories = ["REGISTRATION transaction", "TRANSFER transaction", "SUCCESSION claim"];
  const summary = categories.map((category) => {
    const rows = results.filter((r) => r.category === category);
    const passed = rows.filter((r) => r.ok).length;
    return { category, total: rows.length, passed, failed: rows.length - passed };
  });

  console.log("=== Load test summary ===");
  console.log(`Users registered: ${totalUsers} (${landowners.length} Landowner, ${vos.length} Village Officer, ${registrars.length} Registrar)`);
  console.log(`Registration phase: ${regElapsedMs}ms`);
  for (const s of summary) {
    console.log(`${s.category}: ${s.passed}/${s.total} passed`);
  }
  console.log(`Total elapsed: ${overallElapsedMs}ms`);

  const anyFailed = summary.some((s) => s.failed > 0);

  const failedDetails = results.filter((r) => !r.ok);
  const reportLines = [
    "# Load Test Results",
    "",
    `Run: ${new Date().toISOString()}`,
    "",
    `**Users:** ${totalUsers} total — ${landowners.length} Landowner, ${vos.length} Village Officer, ${registrars.length} Registrar.`,
    `**Registration phase:** ${regElapsedMs}ms for ${totalUsers} users.`,
    "",
    "| Scenario | Total | Passed | Failed | Elapsed |",
    "|---|---|---|---|---|",
    `| REGISTRATION transaction | ${summary[0].total} | ${summary[0].passed} | ${summary[0].failed} | ${registrationElapsedMs}ms |`,
    `| TRANSFER transaction | ${summary[1].total} | ${summary[1].passed} | ${summary[1].failed} | ${transferElapsedMs}ms |`,
    `| SUCCESSION claim (deceased owner + heir) | ${summary[2].total} | ${summary[2].passed} | ${summary[2].failed} | ${successionElapsedMs}ms |`,
    "",
    `**Total elapsed:** ${overallElapsedMs}ms.`,
    "",
  ];
  if (failedDetails.length > 0) {
    reportLines.push("## Failures", "");
    for (const f of failedDetails) {
      reportLines.push(`- **${f.category}**: ${f.detail}`);
    }
    reportLines.push("");
  }

  const reportPath = path.join(process.cwd(), "docs", "load-test-results.md");
  fs.writeFileSync(reportPath, reportLines.join("\n"));
  console.log(`\nResults written to ${reportPath}`);

  if (anyFailed) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
