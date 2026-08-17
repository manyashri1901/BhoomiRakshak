// lib/signing.ts
//
// Generic transaction signing/verification, built on the same canonical-
// JSON + RSA-SHA256 pattern as lib/ca.ts (see lib/canonicalize.ts — shared,
// not duplicated). Where ca.ts signs with the CA's own key to vouch for a
// user's identity, this module signs with a *user's* key to vouch for a
// specific action (registering, transferring, updating a land record).

import * as crypto from "node:crypto";
import { canonicalStringify } from "./canonicalize.ts";

export interface SignResult {
  signatureValue: string;
  dataHash: string;
}

/**
 * Signs an arbitrary transaction payload with the actor's RSA private key.
 *
 * - Canonicalize the payload so signing and later re-verification always
 *   hash/sign byte-identical input (same reasoning as certificate payloads).
 * - dataHash: explicit SHA-256 digest of the canonical payload — this is
 *   what actually gets persisted on the Signature row ("what was signed"),
 *   independent of the signature bytes themselves.
 * - signatureValue: RSA-SHA256 signature over the canonical payload,
 *   base64-encoded for storage in a TEXT column.
 */
export function signTransaction(
  privateKey: string,
  transactionPayload: unknown,
): SignResult {
  const canonicalPayload = canonicalStringify(transactionPayload);
  const payloadBuffer = Buffer.from(canonicalPayload, "utf8");

  const dataHash = crypto
    .createHash("sha256")
    .update(payloadBuffer)
    .digest("hex");

  const signatureValue = crypto
    .sign("RSA-SHA256", payloadBuffer, privateKey)
    .toString("base64");

  return { signatureValue, dataHash };
}

/**
 * Verifies that `signatureValue` is a valid RSA-SHA256 signature by the
 * holder of `publicKey` over `transactionPayload`. Rebuilds the same
 * canonical string signTransaction() would have produced for this payload
 * — if a single field differs from what was originally signed (including
 * something like a tampered documentHash), the rebuilt bytes differ and
 * verification fails, even though the signature itself is well-formed.
 */
export function verifySignature(
  publicKey: string,
  transactionPayload: unknown,
  signatureValue: string,
): boolean {
  const canonicalPayload = canonicalStringify(transactionPayload);
  const payloadBuffer = Buffer.from(canonicalPayload, "utf8");

  try {
    return crypto.verify(
      "RSA-SHA256",
      payloadBuffer,
      publicKey,
      Buffer.from(signatureValue, "base64"),
    );
  } catch {
    // Malformed key/signature — treat as "not valid", not a crash.
    return false;
  }
}
