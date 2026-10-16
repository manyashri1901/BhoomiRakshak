// lib/signing.ts
//
// Transaction signature verification, built on the same canonical-JSON +
// RSA-SHA256 pattern as lib/ca.ts (see lib/canonicalize.ts — shared, not
// duplicated). The server never signs on a user's behalf — every
// transaction-stage signature is produced in the browser
// (frontend/src/lib/clientCrypto.ts) with the user's own private key,
// unwrapped from its encrypted-at-rest form only in memory, for exactly
// as long as it takes to sign. This module only ever verifies.

import * as crypto from "node:crypto";
import { canonicalStringify } from "./canonicalize.ts";

/**
 * Verifies that `signatureValue` is a valid RSA-SHA256 signature by the
 * holder of `publicKey` over `transactionPayload`. Rebuilds the canonical
 * string from the structured payload — if a single field differs from
 * what was originally signed (including something like a tampered
 * documentHash), the rebuilt bytes differ and verification fails, even
 * though the signature itself is well-formed. Used for re-verifying
 * already-recorded signatures (GET .../verify, GET .../history) against
 * payloads rebuilt from current DB state.
 */
export function verifySignature(
  publicKey: string,
  transactionPayload: unknown,
  signatureValue: string,
): boolean {
  const canonicalPayload = canonicalStringify(transactionPayload);
  return verifySignatureOverCanonicalString(publicKey, canonicalPayload, signatureValue);
}

/**
 * Verifies `signatureValue` against an ALREADY-canonical string, with no
 * canonicalStringify() step of its own. Used by the prepare -> sign ->
 * submit flow (routes/transactions.ts): the canonical string was frozen
 * and persisted at prepare time (lib/signingNonce.ts), so submit verifies
 * the browser's signature against those exact stored bytes rather than
 * re-deriving them from a client-supplied structured payload it has no
 * reason to trust.
 */
export function verifySignatureOverCanonicalString(
  publicKey: string,
  canonicalPayload: string,
  signatureValue: string,
): boolean {
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
