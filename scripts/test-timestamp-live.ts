// scripts/test-timestamp-live.ts
//
// One real round trip against TSA_URL: requests a genuine timestamp over a
// throwaway digest, then runs this project's own verifyAnchor() against it
// (same checks a real anchor gets — messageImprint, CMS signature, TSA
// certificate EKU + chain, nonce, genTime), and prints PASS/FAIL. Does not
// touch the database at all (no AuditAnchor row is created) — it builds an
// in-memory anchor-shaped object from a fresh requestTimestampToken() call,
// so it's safe to run against any environment, repeatedly. If the TSA is
// unreachable, this is reported as a clean, expected skip, not a failure —
// the whole point of lib/timestamp.ts's design is that a TSA being down
// must never look like this project's own code being broken.
//
// Run with: node scripts/test-timestamp-live.ts

import "dotenv/config";
import * as crypto from "node:crypto";
import { requestTimestampToken, verifyAnchor, TSA_URL } from "../lib/timestamp.ts";

async function main() {
  console.log(`Requesting a real timestamp from ${TSA_URL}...`);

  const headHash = crypto.createHash("sha256").update(`test-timestamp-live-${Date.now()}`).digest("hex");
  const headHashBytes = Buffer.from(headHash, "hex");

  let requested;
  try {
    requested = await requestTimestampToken(headHashBytes);
  } catch (err) {
    console.log(`SKIP: could not reach ${TSA_URL} (${err instanceof Error ? err.message : "unknown error"}).`);
    console.log("This is treated as an expected, clean skip — a TSA being unreachable is an operational");
    console.log("condition this project is explicitly designed to tolerate (see anchorAuditChainBestEffort()),");
    console.log("not a bug to fail this check over.");
    process.exit(0);
  }

  console.log(`Got a token: genTime ${requested.genTime.toISOString()}, serial ${requested.tsaSerialHex}, policy ${requested.policyOid}`);

  const fakeAnchor = {
    id: "live-test-anchor",
    headLogId: "live-test-head-log",
    headHash,
    tsaUrl: TSA_URL,
    tokenBase64: requested.tokenDer.toString("base64"),
    genTime: requested.genTime,
    tsaSerial: requested.tsaSerialHex,
    policyOid: requested.policyOid,
    nonce: requested.nonceHex,
    createdAt: new Date(),
  };

  // verifyAnchor() also checks steps 7-8 (entryIntact / chainIntact)
  // against the real database by headLogId — "live-test-head-log" won't
  // exist, so those two are EXPECTED to fail here (MISSING), same as
  // scripts/export-cert-check.ts's equivalent caveat. Steps 1-6 — the ones
  // that actually exercise the live TSA round trip — are what this script
  // reports PASS/FAIL on.
  const result = await verifyAnchor(fakeAnchor as Parameters<typeof verifyAnchor>[0]);

  const liveSteps = result.steps.filter((s) => s.id !== "entryIntact" && s.id !== "chainIntact");
  let allPass = true;
  for (const s of liveSteps) {
    console.log(`${s.pass ? "PASS" : "FAIL"} — ${s.label}: ${s.detail}`);
    if (!s.pass) allPass = false;
  }

  if (allPass) {
    console.log("\nPASS — the live TSA round trip is genuine, signed, and independently verifiable.");
    process.exit(0);
  } else {
    console.log("\nFAIL — see above.");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
