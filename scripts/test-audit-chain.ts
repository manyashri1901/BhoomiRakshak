// scripts/test-audit-chain.ts
//
// Fires 20 concurrent appendAuditEntry() calls (simulating 20 simultaneous
// requests all trying to log an action at once) and then verifies that
// the resulting chain has no gaps, no duplicate seqs, and every
// prevHash/hash link is intact — proving the advisory-lock serialization
// in lib/audit.ts prevents a fork under real concurrency, not just in
// theory.
//
// Run with: node scripts/test-audit-chain.ts

import "dotenv/config";
import { prisma } from "../lib/prisma.ts";
import { appendAuditEntry, verifyAuditChain, getAuditHead } from "../lib/audit.ts";

async function main() {
  const before = await getAuditHead();
  console.log("Chain head before:", before);

  const N = 20;
  console.log(`Firing ${N} concurrent appendAuditEntry() calls...`);

  const results = await Promise.all(
    Array.from({ length: N }, (_, i) =>
      appendAuditEntry({
        action: "TEST_CONCURRENT_WRITE",
        entityType: "TEST",
        details: { i },
      }),
    ),
  );

  const seqs = results.map((r) => r.seq).sort((a, b) => a - b);
  const uniqueSeqs = new Set(seqs);
  console.log("Assigned seqs:", seqs);

  if (uniqueSeqs.size !== N) {
    console.error(`FAIL: expected ${N} unique seqs, got ${uniqueSeqs.size} — the chain forked.`);
    process.exit(1);
  }

  // Confirm strictly consecutive (no gaps) among this batch.
  for (let i = 1; i < seqs.length; i++) {
    if (seqs[i] !== seqs[i - 1] + 1) {
      console.error(`FAIL: gap between seq ${seqs[i - 1]} and ${seqs[i]}.`);
      process.exit(1);
    }
  }
  console.log(`PASS: all ${N} seqs are unique and consecutive — no fork under concurrency.`);

  const verification = await verifyAuditChain();
  console.log("verifyAuditChain() result:", verification);
  if (!verification.valid) {
    console.error("FAIL: chain does not verify after concurrent writes.");
    process.exit(1);
  }
  console.log(`PASS: full chain verifies OK (${verification.checked} entries checked).`);

  await prisma.$disconnect();
}

main().catch(async (err) => {
  console.error(err);
  await prisma.$disconnect();
  process.exit(1);
});
