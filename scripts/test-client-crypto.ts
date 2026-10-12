// scripts/test-client-crypto.ts
//
// Runs the ACTUAL browser crypto module (frontend/src/lib/clientCrypto.ts
// — no mocks, no re-implementation) under Node 22's native Web Crypto API
// (globalThis.crypto.subtle), and checks:
//   1. A signature it produces verifies with the server's own
//      node:crypto-based verifySignatureOverCanonicalString (lib/signing.ts).
//   2. canonicalStringify() produces byte-identical output on the frontend
//      copy (frontend/src/lib/canonicalize.ts) and the backend original
//      (lib/canonicalize.ts) for a range of sample payloads.
//   3. A wrong password cannot unwrap a wrapped private key.
//
// Run with: node scripts/test-client-crypto.ts

import {
  generateKeyPair,
  exportPublicKeySpkiPem,
  fingerprintOfPem,
  wrapPrivateKey,
  unwrapPrivateKey,
  signCanonicalString,
  WrongPasswordError,
} from "../frontend/src/lib/clientCrypto.ts";
import { canonicalStringify as canonicalStringifyFrontend } from "../frontend/src/lib/canonicalize.ts";
import { canonicalStringify as canonicalStringifyBackend } from "../lib/canonicalize.ts";
import { verifySignatureOverCanonicalString } from "../lib/signing.ts";

let failures = 0;
function check(label: string, condition: boolean) {
  console.log(`${condition ? "PASS" : "FAIL"}: ${label}`);
  if (!condition) failures++;
}

async function main() {
  // --- 1. Browser-produced signature verifies server-side ---
  const keyPair = await generateKeyPair();
  const publicKeyPem = await exportPublicKeySpkiPem(keyPair.publicKey);
  const samplePayload = canonicalStringifyBackend({
    type: "TRANSFER",
    landRecordId: "lr_abc123",
    documentHash: "e".repeat(64),
    actorId: "user_123",
    nested: { z: 1, a: 2, list: [3, 1, 2] },
  });

  const signature = await signCanonicalString(keyPair.privateKey, samplePayload);
  const serverVerified = verifySignatureOverCanonicalString(publicKeyPem, samplePayload, signature);
  check("browser-produced signature verifies via server's node:crypto", serverVerified);

  const tamperedVerified = verifySignatureOverCanonicalString(
    publicKeyPem,
    samplePayload + " ",
    signature,
  );
  check("signature over a DIFFERENT payload fails to verify", !tamperedVerified);

  // --- 2. Canonical output is byte-identical client vs server ---
  const samples: unknown[] = [
    { b: 1, a: 2 },
    { z: [1, 2, { y: 1, x: 2 }], a: null },
    "plain string",
    42,
    null,
    [1, "two", { three: 3 }],
    { email: "Test@Example.com", fingerprint: "abc123", timestamp: "2026-01-01T00:00:00.000Z" },
  ];
  let allMatch = true;
  for (const sample of samples) {
    const front = canonicalStringifyFrontend(sample);
    const back = canonicalStringifyBackend(sample);
    if (front !== back) {
      allMatch = false;
      console.log(`  mismatch for ${JSON.stringify(sample)}:\n    frontend: ${front}\n    backend:  ${back}`);
    }
  }
  check("canonicalStringify is byte-identical frontend vs backend for all samples", allMatch);

  // --- 3. Wrong password cannot unwrap ---
  const wrapped = await wrapPrivateKey(keyPair.privateKey, "correct-horse-battery-staple");
  let wrongPasswordThrew = false;
  try {
    await unwrapPrivateKey(wrapped, "wrong-password");
  } catch (err) {
    wrongPasswordThrew = err instanceof WrongPasswordError;
  }
  check("wrong password throws WrongPasswordError on unwrap", wrongPasswordThrew);

  const correctUnwrap = await unwrapPrivateKey(wrapped, "correct-horse-battery-staple");
  check("correct password unwraps successfully", correctUnwrap.type === "private");

  const fingerprint = await fingerprintOfPem(publicKeyPem);
  check("fingerprint is 64 hex chars", /^[0-9a-f]{64}$/.test(fingerprint));

  console.log(`\n${failures === 0 ? "ALL PASSED" : `${failures} FAILED`}`);
  if (failures > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
