// lib/canonicalize.ts
//
// Byte-for-byte copy of the backend's lib/canonicalize.ts — see that file
// for the full rationale. Copied rather than imported across the
// frontend/backend module boundary (different bundlers, different
// runtimes) because the registration proof (routes/auth.ts +
// lib/ca.ts's verifyRegistrationProof) is built independently on both
// sides from the same {email, fingerprint, timestamp} fields and must
// canonicalize to identical bytes for the signature to verify. Parity is
// asserted directly by scripts/test-client-crypto.mjs, which imports both
// copies and compares their output for a range of sample payloads — if
// this file and the backend's ever drift, that test fails.
//
// Deterministic JSON serialization. Plain JSON.stringify() does not
// guarantee key order is stable across call sites — two objects with the
// same fields built in a different order can stringify differently, which
// would make a signature computed at one call site fail to verify at
// another even though nothing was tampered with. Sorting keys at every
// nesting level fixes that: the same logical payload always serializes to
// the same exact bytes, anywhere in the app.

export function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalStringify(item)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const entries = sortedKeys.map(
    (key) => `${JSON.stringify(key)}:${canonicalStringify(obj[key])}`,
  );
  return `{${entries.join(",")}}`;
}
