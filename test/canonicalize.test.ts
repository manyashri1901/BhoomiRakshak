// test/canonicalize.test.ts
//
// Determinism of canonicalStringify(): the same logical value always
// produces the same bytes, regardless of the order its keys were built in.

import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalStringify } from "../lib/canonicalize.ts";

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
