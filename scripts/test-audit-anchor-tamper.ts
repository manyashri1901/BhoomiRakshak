// scripts/test-audit-anchor-tamper.ts
//
// THE key security property an RFC 3161 anchor adds over the audit chain's
// own hash links alone: proves nothing AT OR BEFORE the anchored point was
// altered, even by an attacker who recomputes every hash forward from the
// tamper point so the chain's own verifyAuditChain() alone says "valid"
// again. This script does exactly that attack against a real anchor and
// confirms verifyAnchor() still reports TAMPERED — something a plain chain
// walk, taken alone, cannot detect once the forward hashes are "repaired".
//
// This directly tampers with (and permanently recomputes) real AuditLog
// rows — not additive, unlike scripts/test-audit-chain.ts — so, same rule
// as scripts/attack-simulation.ts: refuses to run unless TEST_DATABASE_URL
// is set AND equals DATABASE_URL, as an explicit confirmation the
// configured database is disposable.
//
// Run with: TEST_DATABASE_URL=... node scripts/test-audit-anchor-tamper.ts

import "dotenv/config";

if (!process.env.TEST_DATABASE_URL || process.env.TEST_DATABASE_URL !== process.env.DATABASE_URL) {
  console.error(
    "Refusing to run: TEST_DATABASE_URL is not set, or does not match DATABASE_URL.\n" +
      "This script permanently tampers with and rewrites real AuditLog rows " +
      "and must only ever run against a disposable test database.\n" +
      "Set TEST_DATABASE_URL to the exact same value as DATABASE_URL to confirm that's what you intend.",
  );
  process.exit(1);
}

// Must be set before lib/timestamp.ts is first imported below — it reads
// TSA_MIN_INTERVAL_SECONDS once, at import time, same as TSA_URL/
// TSA_TIMEOUT_MS. This script needs to anchor twice in quick succession
// without waiting on the real production interval.
process.env.TSA_MIN_INTERVAL_SECONDS = "0";

import assert from "node:assert/strict";
import { prisma } from "../lib/prisma.ts";
import { appendAuditEntry, verifyAuditChain, computeEntryHash } from "../lib/audit.ts";
import { anchorAuditChain, verifyAnchor } from "../lib/timestamp.ts";

async function main() {
  console.log("Appending a few audit entries to establish a chain position to anchor...");
  for (let i = 0; i < 3; i += 1) {
    await appendAuditEntry({ action: "TEST_ANCHOR_TAMPER_SETUP", entityType: "TEST", details: { i } });
  }

  console.log("Anchoring the current head...");
  const anchorResult = await anchorAuditChain();
  if (anchorResult.outcome !== "anchored") {
    console.error(`FAIL: expected to anchor, got outcome "${anchorResult.outcome}"${"reason" in anchorResult ? `: ${anchorResult.reason}` : ""}.`);
    process.exit(1);
  }
  console.log(`Anchored at seq ${anchorResult.headSeq} (genTime ${anchorResult.genTime.toISOString()}).`);
  const anchoredSeq = anchorResult.headSeq;

  const anchorRow = await prisma.auditAnchor.findFirst({
    where: { headLog: { seq: anchoredSeq } },
    orderBy: { createdAt: "desc" },
  });
  if (!anchorRow) {
    console.error("FAIL: could not read back the anchor row just created.");
    process.exit(1);
  }

  console.log("\nStep 1: verify the fresh anchor is VALID before any tampering...");
  const beforeTamper = await verifyAnchor(anchorRow);
  assert.equal(beforeTamper.status, "VALID", `expected VALID before tampering, got ${beforeTamper.status}`);
  console.log("  PASS — fresh anchor verifies VALID.");

  console.log("\nStep 2: append a few more entries after the anchored point (normal activity)...");
  for (let i = 0; i < 2; i += 1) {
    await appendAuditEntry({ action: "TEST_ANCHOR_TAMPER_AFTER", entityType: "TEST", details: { i } });
  }

  console.log("\nStep 3: attack — directly corrupt the ANCHORED entry's details, then recompute every");
  console.log("hash forward from it, exactly as a sophisticated attacker with raw DB access would, so");
  console.log("the chain's OWN links look internally consistent again...");

  const entries = await prisma.auditLog.findMany({ where: { seq: { gte: anchoredSeq } }, orderBy: { seq: "asc" } });
  const anchoredEntry = entries[0];
  assert.equal(anchoredEntry.seq, anchoredSeq);

  let prevHash = anchoredEntry.prevHash;
  for (const entry of entries) {
    const tamperedDetails = entry.seq === anchoredSeq ? { tampered: true } : (entry.details as Record<string, unknown>);
    const newHash = computeEntryHash({
      seq: entry.seq,
      action: entry.action,
      actorUserId: entry.actorUserId,
      entityType: entry.entityType,
      entityId: entry.entityId,
      details: tamperedDetails,
      nonce: entry.nonce,
      timestamp: entry.timestamp.toISOString(),
      prevHash,
    });
    await prisma.auditLog.update({
      where: { id: entry.id },
      data: { details: tamperedDetails, prevHash, hash: newHash },
    });
    prevHash = newHash;
  }
  console.log(`  Rewrote seq ${anchoredSeq}..${entries[entries.length - 1].seq} with consistent forward-recomputed hashes.`);

  console.log("\nStep 4: the PLAIN chain check alone — does it still report valid? (it should: that's the whole point)");
  const chainAfter = await verifyAuditChain();
  assert.equal(chainAfter.valid, true, "expected the plain chain walk to report valid after the forward-recompute");
  console.log("  CONFIRMED — verifyAuditChain() alone says valid: true. A plain hash-chain check cannot tell this happened.");

  console.log("\nStep 5: does verifyAnchor() still catch it?");
  const afterTamper = await verifyAnchor(anchorRow);
  const entryIntact = afterTamper.steps.find((s) => s.id === "entryIntact");
  console.log(`  entryIntact: ${entryIntact?.pass ? "PASS" : "FAIL"} — ${entryIntact?.detail}`);
  assert.equal(afterTamper.status, "TAMPERED", `expected TAMPERED, got ${afterTamper.status}`);
  assert.equal(entryIntact?.pass, false, "expected the entryIntact step specifically to fail");
  console.log(`  PASS — verifyAnchor() reports status "${afterTamper.status}" even though the plain chain check alone passed.`);

  console.log("\nAll checks passed — RFC 3161 anchoring catches a forward-recomputed tamper a plain chain walk cannot.");
  await prisma.$disconnect();
}

main().catch(async (err) => {
  console.error(err);
  await prisma.$disconnect();
  process.exit(1);
});
