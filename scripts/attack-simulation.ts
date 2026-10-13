// scripts/attack-simulation.ts
//
// Runs a battery of real attacks against a RUNNING server (node server.ts
// on localhost:4000), using the actual client-crypto module
// (frontend/src/lib/clientCrypto.ts — no mocks) to create real users and
// real signatures, then tries to break the system with each one. Every
// attack is expected to be BLOCKED; the script prints a table of
// ATTACK | EXPECTED | ACTUAL | PASS/FAIL and exits non-zero if any attack
// actually succeeded (i.e. the system failed to block it).
//
// Run with: node scripts/attack-simulation.ts
// (server must already be running: node server.ts)
//
// This paste into the case-study report as-is; it is the "attack table".

import "dotenv/config";
import * as crypto from "node:crypto";
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
import { prisma } from "../lib/prisma.ts";
import { computeEntryHash } from "../lib/audit.ts";

const BASE = "http://localhost:4000/api";
const PASSWORD = "attacktest123";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL ?? "shrimanya2@gmail.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD ?? "AdminPass123!";

interface AttackResult {
  attack: string;
  expected: string;
  actual: string;
  pass: boolean;
}

const results: AttackResult[] = [];

function record(attack: string, expected: string, actual: string, pass: boolean) {
  results.push({ attack, expected, actual, pass });
}

// Several attacks first need a genuine, successfully-created transaction to
// attack (e.g. "skip a stage on it"). If that setup step itself fails —
// rate limiting, a dropped connection, anything — using its (undefined)
// .data.id would silently turn a setup failure into a confusing, unrelated
// "attack succeeded" result (e.g. a 404 from calling an endpoint with
// literally the string "undefined" as the id). Fail loudly instead.
function assertSetupOk(res: { status: number; data: unknown }, label: string) {
  if (res.status !== 201) {
    throw new Error(`Setup step failed, aborting: ${label} — HTTP ${res.status}: ${JSON.stringify(res.data)}`);
  }
}

// Markdown table cells can't contain a literal "|" or a newline without
// breaking the table — escape/flatten both rather than assume no attack's
// expected/actual text ever contains one.
function mdCell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function truncate(value: string, maxLength: number): string {
  return value.length > maxLength ? value.slice(0, maxLength - 1) + "…" : value;
}

// Writes the same results the console table already showed out to
// docs/attack-results.md, so the attack table can be pasted into (or
// linked from) the case-study report without re-running the script and
// copying terminal output by hand. Pure reporting — no effect on any
// attack's pass/fail logic above.
function writeMarkdownReport(allResults: AttackResult[], blockedCount: number) {
  const docsDir = path.join(process.cwd(), "docs");
  fs.mkdirSync(docsDir, { recursive: true });

  const lines: string[] = [];
  lines.push("# Attack Simulation Results");
  lines.push("");
  lines.push(`Run: ${new Date().toISOString()}`);
  lines.push("");
  lines.push(`**${blockedCount} of ${allResults.length} attacks blocked**`);
  lines.push("");
  lines.push("| # | Attack | Expected defence | Actual response | Result |");
  lines.push("|---|---|---|---|---|");
  allResults.forEach((r, i) => {
    lines.push(
      `| ${i} | ${mdCell(r.attack)} | ${mdCell(r.expected)} | ${mdCell(truncate(r.actual, 80))} | ${r.pass ? "PASS (blocked)" : "FAIL (succeeded!)"} |`,
    );
  });
  lines.push("");

  fs.writeFileSync(path.join(docsDir, "attack-results.md"), lines.join("\n"), "utf8");
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

interface SimUser {
  id: string;
  email: string;
  token: string;
  wrappedKey: { ciphertext: string; salt: string; iv: string };
  publicKeyPem: string;
  keyPair: CryptoKeyPair;
}

async function registerUser(name: string, email: string, role: string): Promise<SimUser> {
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
  if (registerRes.status !== 201) throw new Error(`Registration failed for ${email}: ${JSON.stringify(registerBody)}`);

  const loginRes = await fetch(`${BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: PASSWORD }),
  });
  const loginBody = await loginRes.json();
  if (loginRes.status !== 200) throw new Error(`Login failed for ${email}: ${JSON.stringify(loginBody)}`);

  return { id: registerBody.id, email, token: loginBody.token, wrappedKey: loginBody.wrappedKey, publicKeyPem, keyPair };
}

async function uploadPdf(token: string, content: string, filename = "doc.pdf") {
  const formData = new FormData();
  formData.append("file", new Blob([content], { type: "application/pdf" }), filename);
  const res = await fetch(`${BASE}/documents/upload`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: formData,
  });
  return { status: res.status, data: await res.json() };
}

async function createApprovedLandRecord(registrarToken: string, ownerId: string, surveyNumber: string) {
  const res = await api("/land-records", registrarToken, "POST", {
    surveyNumber,
    location: "Attack Sim Village",
    area: 1,
    currentOwnerId: ownerId,
  });
  return res.data.id as string;
}

async function main() {
  const stamp = Date.now();
  const landowner = await registerUser("Attack Landowner", `atk-lo-${stamp}@example.com`, "LANDOWNER");
  const landowner2 = await registerUser("Attack Landowner 2", `atk-lo2-${stamp}@example.com`, "LANDOWNER");
  const vo = await registerUser("Attack VO", `atk-vo-${stamp}@example.com`, "VILLAGE_OFFICER");
  const registrar = await registerUser("Attack Registrar", `atk-reg-${stamp}@example.com`, "REGISTRAR");
  const outsider = await generateKeyPair(); // never registered — used for forged signatures

  const adminLogin = await api("/auth/login", null, "POST", { email: ADMIN_EMAIL, password: ADMIN_PASSWORD });
  if (adminLogin.status !== 200) {
    throw new Error(
      `Admin login failed (HTTP ${adminLogin.status}): ${JSON.stringify(adminLogin.data)} — ` +
        `set ADMIN_EMAIL/ADMIN_PASSWORD env vars to match an existing ADMIN account.`,
    );
  }
  const adminToken = adminLogin.data.token;

  // =========================================================================
  // 1. Tampered document (hash mismatch)
  // =========================================================================
  {
    const lrId = await createApprovedLandRecord(registrar.token, landowner.id, `SN-ATK-DOC-${stamp}`);
    const upload = await uploadPdf(landowner.token, `%PDF-1.4\ndoc ${stamp}`);
    const prep = await api("/transactions/prepare", landowner.token, "POST", {
      type: "REGISTRATION",
      landRecordId: lrId,
      documentPath: upload.data.documentPath,
      documentHash: upload.data.documentHash,
    });
    const loKey = await unwrapPrivateKey(landowner.wrappedKey, PASSWORD);
    const sig = await signCanonicalString(loKey, prep.data.payload);
    const submit = await api("/transactions/submit", landowner.token, "POST", { nonce: prep.data.nonce, signatureValue: sig });
    assertSetupOk(submit, "create transaction for tampered-document attack");
    const txnId = submit.data.id;

    // Attacker with raw DB access swaps the recorded hash for an unrelated one.
    const tamperedHash = crypto.randomBytes(32).toString("hex");
    await prisma.transaction.update({ where: { id: txnId }, data: { documentHash: tamperedHash } });

    const verify = await api(`/transactions/${txnId}/verify`, registrar.token, "GET");
    const detected = verify.data?.documentIntegrity?.match === false;
    record(
      "Tampered document (hash mismatch)",
      "documentIntegrity.match = false",
      `documentIntegrity.match = ${verify.data?.documentIntegrity?.match}`,
      detected,
    );
  }

  // =========================================================================
  // 2. Forged signature (signed by a key never registered with the CA)
  // =========================================================================
  {
    const lrId = await createApprovedLandRecord(registrar.token, landowner.id, `SN-ATK-FORGE-${stamp}`);
    const upload = await uploadPdf(landowner.token, `%PDF-1.4\nforge ${stamp}`);
    const prep = await api("/transactions/prepare", landowner.token, "POST", {
      type: "REGISTRATION",
      landRecordId: lrId,
      documentPath: upload.data.documentPath,
      documentHash: upload.data.documentHash,
    });
    const forgedSig = await signCanonicalString(outsider.privateKey, prep.data.payload);
    const submit = await api("/transactions/submit", landowner.token, "POST", {
      nonce: prep.data.nonce,
      signatureValue: forgedSig,
    });
    record(
      "Forged signature (unregistered key)",
      "submit rejected (409/400)",
      `HTTP ${submit.status}: ${submit.data?.error}`,
      submit.status >= 400,
    );
  }

  // =========================================================================
  // 3. Signature from the wrong (registered) key
  // =========================================================================
  {
    const lrId = await createApprovedLandRecord(registrar.token, landowner.id, `SN-ATK-WRONGKEY-${stamp}`);
    const upload = await uploadPdf(landowner.token, `%PDF-1.4\nwrongkey ${stamp}`);
    const prep = await api("/transactions/prepare", landowner.token, "POST", {
      type: "REGISTRATION",
      landRecordId: lrId,
      documentPath: upload.data.documentPath,
      documentHash: upload.data.documentHash,
    });
    const registrarKey = await unwrapPrivateKey(registrar.wrappedKey, PASSWORD);
    const wrongSig = await signCanonicalString(registrarKey, prep.data.payload);
    const submit = await api("/transactions/submit", landowner.token, "POST", {
      nonce: prep.data.nonce,
      signatureValue: wrongSig,
    });
    record(
      "Signature from the wrong key (another real user's key)",
      "submit rejected (409/400)",
      `HTTP ${submit.status}: ${submit.data?.error}`,
      submit.status >= 400,
    );
  }

  // =========================================================================
  // 4. Revoked certificate
  // =========================================================================
  {
    const victim = await registerUser("Attack Revoke Victim", `atk-revoke-${stamp}@example.com`, "LANDOWNER");
    const certLookup = await api(`/certificates/${victim.id}`, adminToken, "GET");
    await api(`/certificates/${certLookup.data.id}/revoke`, adminToken, "POST", { reason: "Attack simulation" });

    const lrId = await createApprovedLandRecord(registrar.token, victim.id, `SN-ATK-REVOKED-${stamp}`);
    const upload = await uploadPdf(victim.token, `%PDF-1.4\nrevoked ${stamp}`);
    const prep = await api("/transactions/prepare", victim.token, "POST", {
      type: "REGISTRATION",
      landRecordId: lrId,
      documentPath: upload.data.documentPath,
      documentHash: upload.data.documentHash,
    });
    record(
      "Revoked certificate used to sign",
      "prepare rejected 403 before any signing",
      `HTTP ${prep.status}: ${prep.data?.error}`,
      prep.status === 403,
    );
  }

  // =========================================================================
  // 5. Expired certificate (correctly signed by the CA, but past expiresAt)
  // =========================================================================
  {
    const victim = await registerUser("Attack Expiry Victim", `atk-expiry-${stamp}@example.com`, "LANDOWNER");
    const cert = await prisma.certificate.findUnique({ where: { subjectUserId: victim.id } });
    const caPrivateKey = (await import("node:fs")).readFileSync(
      (await import("node:path")).join(process.cwd(), "keys", "ca-private.pem"),
      "utf8",
    );
    const issuedAt = new Date(Date.now() - 2 * 365 * 24 * 60 * 60 * 1000);
    const expiresAt = new Date(issuedAt.getTime() + 365 * 24 * 60 * 60 * 1000);
    const payload = {
      subject: victim.id,
      name: "Attack Expiry Victim",
      role: "LANDOWNER",
      publicKey: cert!.publicKey,
      issuer: cert!.issuer,
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
    };
    const canonical = canonicalStringify(payload);
    const signature = crypto.sign("RSA-SHA256", Buffer.from(canonical, "utf8"), caPrivateKey).toString("base64");
    await prisma.certificate.update({ where: { id: cert!.id }, data: { issuedAt, expiresAt, signature } });

    const lrId = await createApprovedLandRecord(registrar.token, victim.id, `SN-ATK-EXPIRED-${stamp}`);
    const upload = await uploadPdf(victim.token, `%PDF-1.4\nexpired ${stamp}`);
    const prep = await api("/transactions/prepare", victim.token, "POST", {
      type: "REGISTRATION",
      landRecordId: lrId,
      documentPath: upload.data.documentPath,
      documentHash: upload.data.documentHash,
    });
    record(
      "Expired certificate used to sign",
      "prepare rejected 403 before any signing",
      `HTTP ${prep.status}: ${prep.data?.error}`,
      prep.status === 403,
    );
  }

  // =========================================================================
  // 6. Replayed nonce
  // =========================================================================
  {
    const lrId = await createApprovedLandRecord(registrar.token, landowner.id, `SN-ATK-REPLAY-${stamp}`);
    const upload = await uploadPdf(landowner.token, `%PDF-1.4\nreplay ${stamp}`);
    const prep = await api("/transactions/prepare", landowner.token, "POST", {
      type: "REGISTRATION",
      landRecordId: lrId,
      documentPath: upload.data.documentPath,
      documentHash: upload.data.documentHash,
    });
    const loKey = await unwrapPrivateKey(landowner.wrappedKey, PASSWORD);
    const sig = await signCanonicalString(loKey, prep.data.payload);
    const first = await api("/transactions/submit", landowner.token, "POST", { nonce: prep.data.nonce, signatureValue: sig });
    const replay = await api("/transactions/submit", landowner.token, "POST", { nonce: prep.data.nonce, signatureValue: sig });
    record(
      "Replayed (already-used) nonce",
      "first submit 201, replay rejected 409",
      `first HTTP ${first.status}, replay HTTP ${replay.status}: ${replay.data?.error}`,
      first.status === 201 && replay.status === 409,
    );
  }

  // =========================================================================
  // 7. Wrong-role approval (a Landowner tries to act as Village Officer)
  // =========================================================================
  {
    const lrId = await createApprovedLandRecord(registrar.token, landowner.id, `SN-ATK-ROLE-${stamp}`);
    const upload = await uploadPdf(landowner.token, `%PDF-1.4\nrole ${stamp}`);
    const prep = await api("/transactions/prepare", landowner.token, "POST", {
      type: "REGISTRATION",
      landRecordId: lrId,
      documentPath: upload.data.documentPath,
      documentHash: upload.data.documentHash,
    });
    const loKey = await unwrapPrivateKey(landowner.wrappedKey, PASSWORD);
    const sig = await signCanonicalString(loKey, prep.data.payload);
    const submit = await api("/transactions/submit", landowner.token, "POST", { nonce: prep.data.nonce, signatureValue: sig });
    assertSetupOk(submit, "create transaction for wrong-role attack");
    const txnId = submit.data.id;

    // The landowner who just created this transaction tries to also
    // approve it as if they were the Village Officer.
    const wrongRole = await api(`/transactions/${txnId}/vo-review/prepare`, landowner.token, "POST");
    record(
      "Wrong-role approval (Landowner acting as Village Officer)",
      "rejected 403 (role check)",
      `HTTP ${wrongRole.status}: ${wrongRole.data?.error}`,
      wrongRole.status === 403,
    );
  }

  // =========================================================================
  // 8. Skipped stage (Registrar approves before Village Officer has)
  // =========================================================================
  {
    const lrId = await createApprovedLandRecord(registrar.token, landowner.id, `SN-ATK-SKIP-${stamp}`);
    const upload = await uploadPdf(landowner.token, `%PDF-1.4\nskip ${stamp}`);
    const prep = await api("/transactions/prepare", landowner.token, "POST", {
      type: "REGISTRATION",
      landRecordId: lrId,
      documentPath: upload.data.documentPath,
      documentHash: upload.data.documentHash,
    });
    const loKey = await unwrapPrivateKey(landowner.wrappedKey, PASSWORD);
    const sig = await signCanonicalString(loKey, prep.data.payload);
    const submit = await api("/transactions/submit", landowner.token, "POST", { nonce: prep.data.nonce, signatureValue: sig });
    assertSetupOk(submit, "create transaction for skip-stage attack");
    const txnId = submit.data.id;

    // Still PENDING_VO — Registrar tries to jump straight to their own stage.
    const skip = await api(`/transactions/${txnId}/registrar-review/prepare`, registrar.token, "POST");
    record(
      "Skipped stage (Registrar before Village Officer)",
      "rejected 400 (not pending Registrar review)",
      `HTTP ${skip.status}: ${skip.data?.error}`,
      skip.status === 400,
    );
  }

  // =========================================================================
  // 9. Double sale, WITH a genuine race: two simultaneous prepare+submit
  //    sequences against the SAME land record.
  // =========================================================================
  {
    const lrId = await createApprovedLandRecord(registrar.token, landowner.id, `SN-ATK-DOUBLESALE-${stamp}`);
    const uploadA = await uploadPdf(landowner.token, `%PDF-1.4\ndoubleA ${stamp}`, "a.pdf");
    const uploadB = await uploadPdf(landowner.token, `%PDF-1.4\ndoubleB ${stamp}`, "b.pdf");
    const loKey = await unwrapPrivateKey(landowner.wrappedKey, PASSWORD);

    // Both prepares fire concurrently — neither has written anything yet,
    // so both legitimately see the land record as ACTIVE.
    const [prepA, prepB] = await Promise.all([
      api("/transactions/prepare", landowner.token, "POST", {
        type: "REGISTRATION",
        landRecordId: lrId,
        documentPath: uploadA.data.documentPath,
        documentHash: uploadA.data.documentHash,
      }),
      api("/transactions/prepare", landowner.token, "POST", {
        type: "REGISTRATION",
        landRecordId: lrId,
        documentPath: uploadB.data.documentPath,
        documentHash: uploadB.data.documentHash,
      }),
    ]);
    const sigA = await signCanonicalString(loKey, prepA.data.payload);
    const sigB = await signCanonicalString(loKey, prepB.data.payload);

    // Both submits fire concurrently — the DB's partial unique index
    // decides which one actually wins the INSERT.
    const [submitA, submitB] = await Promise.all([
      api("/transactions/submit", landowner.token, "POST", { nonce: prepA.data.nonce, signatureValue: sigA }),
      api("/transactions/submit", landowner.token, "POST", { nonce: prepB.data.nonce, signatureValue: sigB }),
    ]);
    const statuses = [submitA.status, submitB.status].sort();
    const exactlyOneWon = statuses[0] === 201 && statuses[1] === 409;
    record(
      "Double sale (race: 2 simultaneous prepare+submit on same record)",
      "exactly one submit 201, the other 409",
      `submitA HTTP ${submitA.status}, submitB HTTP ${submitB.status}`,
      exactlyOneWon,
    );
  }

  // =========================================================================
  // 10. Tampered audit log (disposable test row, then restored)
  //
  // Checked by LOCAL hash recomputation (computeEntryHash, lib/audit.ts) on
  // this one row, rather than solely on whole-chain verifyAuditChain().valid
  // — a long-lived shared dev database can carry earlier, unrelated breaks
  // (this one does: see the Day 5 report), and verifyAuditChain() always
  // reports the EARLIEST break it finds scanning from seq 1, which would
  // mask whether THIS row's own tamper-then-restore cycle worked. Recomputing
  // this row's hash directly proves the mechanism on this row alone,
  // independent of anything else in the table. The whole-chain result is
  // still captured and printed for visibility, not as the pass/fail gate.
  // =========================================================================
  {
    const head = await api("/audit/head", adminToken, "GET");
    if (head.status !== 200 || typeof head.data?.seq !== "number") {
      throw new Error(`GET /audit/head failed (HTTP ${head.status}): ${JSON.stringify(head.data)}`);
    }
    const targetSeq = head.data.seq; // the freshest entry — nothing depends on it yet
    const row = await prisma.auditLog.findUnique({ where: { seq: targetSeq } });
    const hashOf = (r: typeof row) =>
      computeEntryHash({
        seq: r!.seq,
        action: r!.action,
        actorUserId: r!.actorUserId,
        entityType: r!.entityType,
        entityId: r!.entityId,
        details: r!.details,
        nonce: r!.nonce,
        timestamp: r!.timestamp.toISOString(),
        prevHash: r!.prevHash,
      });

    const originalDetails = row!.details as object;
    const matchesBeforeTamper = hashOf(row) === row!.hash;

    await prisma.$executeRawUnsafe(
      `UPDATE audit_logs SET details = '{"attackSimulation":true}'::jsonb WHERE seq = $1`,
      targetSeq,
    );
    const tamperedRow = await prisma.auditLog.findUnique({ where: { seq: targetSeq } });
    const mismatchAfterTamper = hashOf(tamperedRow) !== tamperedRow!.hash;
    const wholeChainAfterTamper = await api("/audit/verify", adminToken, "GET");

    // Restore.
    await prisma.auditLog.update({ where: { seq: targetSeq }, data: { details: originalDetails } });
    const restoredRow = await prisma.auditLog.findUnique({ where: { seq: targetSeq } });
    const matchesAfterRestore = hashOf(restoredRow) === restoredRow!.hash;

    record(
      "Tampered audit log row (then restored)",
      "row's own hash matches before tamper, mismatches after tamper, matches again after restore",
      `before=${matchesBeforeTamper}, after tamper=${!mismatchAfterTamper ? "still matches (BAD)" : "mismatch (detected)"}, after restore=${matchesAfterRestore}` +
        ` [whole-chain verify at time of tamper: valid=${wholeChainAfterTamper.data?.valid}, firstBrokenSeq=${wholeChainAfterTamper.data?.firstBrokenSeq}]`,
      matchesBeforeTamper && mismatchAfterTamper && matchesAfterRestore,
    );
  }

  // =========================================================================
  // 11. Upload of a fake PDF (.exe content, .pdf claimed)
  // =========================================================================
  {
    const fakeUpload = await uploadPdf(landowner.token, "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00not a real pdf");
    record(
      "Upload of a fake PDF (EXE magic bytes, .pdf filename)",
      "rejected 415 before touching disk",
      `HTTP ${fakeUpload.status}: ${fakeUpload.data?.error}`,
      fakeUpload.status === 415,
    );
  }

  // =========================================================================
  // 12. Non-admin calling revoke
  // =========================================================================
  {
    const certLookup = await api(`/certificates/${landowner2.id}`, adminToken, "GET");
    const nonAdminRevoke = await api(`/certificates/${certLookup.data.id}/revoke`, landowner.token, "POST", {
      reason: "Attack simulation — should not be allowed",
    });
    record(
      "Non-admin calling certificate revoke",
      "rejected 403 (role check)",
      `HTTP ${nonAdminRevoke.status}: ${nonAdminRevoke.data?.error}`,
      nonAdminRevoke.status === 403,
    );
  }

  // =========================================================================
  // Print results table + summary
  // =========================================================================
  console.log("\n");
  console.table(
    results.map((r) => ({
      ATTACK: r.attack,
      EXPECTED: r.expected,
      ACTUAL: r.actual,
      "PASS/FAIL": r.pass ? "PASS (blocked)" : "FAIL (succeeded!)",
    })),
  );

  const blocked = results.filter((r) => r.pass).length;
  console.log(`\n${blocked} of ${results.length} attacks blocked`);

  writeMarkdownReport(results, blocked);

  await prisma.$disconnect();
  if (blocked !== results.length) {
    process.exit(1);
  }
}

main().catch(async (err) => {
  console.error(err);
  await prisma.$disconnect();
  process.exit(1);
});
