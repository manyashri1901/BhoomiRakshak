// test/canonicalize.test.ts
//
// Determinism of canonicalStringify(): the same logical value always
// produces the same bytes, regardless of the order its keys were built in.

import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalStringify } from "../lib/canonicalize.ts";
import { canonicalStringify as canonicalStringifyFrontend } from "../frontend/src/lib/canonicalize.ts";

// Shared fixed test vector: the browser builds the exact same canonical
// registration-proof-of-possession string the backend rebuilds and checks
// (lib/ca.ts's verifyRegistrationProof(), frontend's registration flow),
// using its OWN copy of canonicalize.ts (never imported across the
// frontend/backend boundary — see that file's header). Certificates and
// their revocation list are real X.509 now (@peculiar/x509, not
// canonicalStringify) — this proof-of-possession payload is the one
// remaining place both copies must agree on byte-for-byte. If the two
// copies ever drift even one character, every registration's proof of
// key possession would silently fail to verify. This one fixed payload,
// with its expected output hard-coded literally (not just "do the two
// agree with each other" — that alone wouldn't catch both copies drifting
// the same way), is checked against both copies so any future edit to
// either file that changes its behavior fails this test immediately.
const SHARED_TEST_VECTOR = {
  email: "test@example.com",
  fingerprint: "a1b2c3d4e5f6",
  timestamp: "2026-01-01T00:00:00.000Z",
};
const EXPECTED_CANONICAL =
  '{"email":"test@example.com","fingerprint":"a1b2c3d4e5f6","timestamp":"2026-01-01T00:00:00.000Z"}';

test("shared vector: backend canonicalStringify matches the hard-coded expected output", () => {
  assert.equal(canonicalStringify(SHARED_TEST_VECTOR), EXPECTED_CANONICAL);
});

test("shared vector: frontend's copy of canonicalStringify matches the exact same expected output", () => {
  assert.equal(canonicalStringifyFrontend(SHARED_TEST_VECTOR), EXPECTED_CANONICAL);
});

test("same keys in a different order produce identical output", () => {
  const a = canonicalStringify({ b: 1, a: 2, c: 3 });
  const b = canonicalStringify({ c: 3, a: 2, b: 1 });
  assert.equal(a, b);
  assert.equal(a, '{"a":2,"b":1,"c":3}');
});

test("nested objects are sorted at every level", () => {
  const a = canonicalStringify({ outer: { z: 1, a: 2 }, first: true });
  const b = canonicalStringify({ first: true, outer: { a: 2, z: 1 } });
  assert.equal(a, b);
});

test("arrays preserve order (not sorted) but their contents canonicalize", () => {
  const out = canonicalStringify({ list: [{ b: 1, a: 2 }, { d: 1, c: 2 }] });
  assert.equal(out, '{"list":[{"a":2,"b":1},{"c":2,"d":1}]}');
});

test("primitives and null round-trip through JSON.stringify", () => {
  assert.equal(canonicalStringify(null), "null");
  assert.equal(canonicalStringify(42), "42");
  assert.equal(canonicalStringify("x"), '"x"');
  assert.equal(canonicalStringify(true), "true");
});

test("a changed value (not just key order) produces different output", () => {
  const a = canonicalStringify({ amount: 100 });
  const b = canonicalStringify({ amount: 101 });
  assert.notEqual(a, b);
});
