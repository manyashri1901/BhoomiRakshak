// test/canonicalize.test.ts
//
// Determinism of canonicalStringify(): the same logical value always
// produces the same bytes, regardless of the order its keys were built in.

import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalStringify } from "../lib/canonicalize.ts";
import { canonicalStringify as canonicalStringifyFrontend } from "../frontend/src/lib/canonicalize.ts";

// Shared fixed test vector (certificate-rework task): the frontend's new
// client-side verify helper (frontend/src/lib/certificateVerify.ts)
// rebuilds the exact same canonical certificate/CRL payloads the backend
// signs, using its OWN copy of canonicalize.ts (never imported across the
// frontend/backend boundary — see that file's header). If the two copies
// ever drift even one character, every signature the frontend tries to
// verify would silently fail. This one fixed payload, with its expected
// output hard-coded literally (not just "do the two agree with each
// other" — that alone wouldn't catch both copies drifting the same way),
// is checked against both copies so any future edit to either file that
// changes its behavior fails this test immediately.
const SHARED_TEST_VECTOR = {
  type: "CRL",
  issuer: "BhoomiRakshak Root CA",
  thisUpdate: "2026-01-01T00:00:00.000Z",
  nextUpdate: "2026-01-01T01:00:00.000Z",
  revokedSerials: ["cert_b", "cert_a"],
};
const EXPECTED_CANONICAL =
  '{"issuer":"BhoomiRakshak Root CA","nextUpdate":"2026-01-01T01:00:00.000Z","revokedSerials":["cert_b","cert_a"],"thisUpdate":"2026-01-01T00:00:00.000Z","type":"CRL"}';

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
