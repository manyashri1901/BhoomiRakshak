// lib/canonicalize.ts
//
// Deterministic JSON serialization, shared by every module that signs or
// hashes a payload (lib/ca.ts, lib/signing.ts). Plain JSON.stringify() does
// not guarantee key order is stable across call sites — two objects with
// the same fields built in a different order can stringify differently,
// which would make a signature computed at one call site fail to verify
// at another even though nothing was tampered with. Sorting keys at every
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
