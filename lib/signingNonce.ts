// lib/signingNonce.ts
//
// Backs the prepare -> sign -> submit flow for every client-side signature
// (transaction creation, VO review, registrar review — routes/transactions.ts).
//
// prepare: the server decides and freezes the exact canonical string that
// must be signed, computes its SHA-256, and stores both under a fresh,
// single-use nonce with a short expiry. Only {nonce, payload, payloadHash}
// go back to the browser.
//
// submit: the browser sends back {nonce, signatureValue} — never the
// payload itself. The server looks the nonce up, checks it's unused,
// unexpired, and was issued to this exact user for this exact purpose (and
// transaction, where applicable), marks it used, and only then hands the
// frozen payload string back to the caller to verify the signature
// against. A client can never substitute a different payload for the one
// that was actually frozen at prepare time.

import * as crypto from "node:crypto";
import { prisma } from "./prisma.ts";
import type { Prisma } from "../generated/prisma/client.ts";

const NONCE_VALIDITY_MS = 5 * 60 * 1000;

export type SigningPurpose =
  | "TRANSACTION_CREATE"
  | "VO_REVIEW_APPROVE"
  | "REGISTRAR_REVIEW_APPROVE";

export interface CreateSigningNonceInput {
  userId: string;
  purpose: SigningPurpose;
  transactionId?: string | null;
  canonicalPayload: string;
}

export interface PreparedSignature {
  nonce: string;
  payload: string;
  payloadHash: string;
  expiresAt: string;
}

export async function createSigningNonce(
  input: CreateSigningNonceInput,
): Promise<PreparedSignature> {
  const nonce = crypto.randomBytes(32).toString("hex");
  const payloadHash = crypto.createHash("sha256").update(input.canonicalPayload, "utf8").digest("hex");
  const expiresAt = new Date(Date.now() + NONCE_VALIDITY_MS);

  await prisma.signingNonce.create({
    data: {
      nonce,
      userId: input.userId,
      purpose: input.purpose,
      transactionId: input.transactionId ?? null,
      payload: input.canonicalPayload,
      payloadHash,
      expiresAt,
    },
  });

  return { nonce, payload: input.canonicalPayload, payloadHash, expiresAt: expiresAt.toISOString() };
}

export class SigningNonceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SigningNonceError";
  }
}

export interface ConsumeSigningNonceInput {
  nonce: string;
  userId: string;
  purpose: SigningPurpose;
  // Required when the purpose is scoped to an existing transaction (both
  // review purposes) — omit only for TRANSACTION_CREATE, where the
  // transaction doesn't exist until submit creates it.
  transactionId?: string | null;
}

/**
 * Validates and consumes a nonce inside the caller's own transaction (`db`)
 * — marking it used is atomic with the business write and audit entry it
 * gates, so a crash or error after this point can never leave a nonce
 * marked used without the signature it authorized actually having been
 * recorded. Throws SigningNonceError with a specific, user-facing reason
 * for every way a nonce can fail to apply; callers map that straight to a
 * 400/409 response.
 */
export async function consumeSigningNonce(
  db: Prisma.TransactionClient,
  input: ConsumeSigningNonceInput,
): Promise<{ payload: string; payloadHash: string }> {
  const row = await db.signingNonce.findUnique({ where: { nonce: input.nonce } });

  if (!row) throw new SigningNonceError("Unknown nonce — call prepare again.");
  if (row.userId !== input.userId) throw new SigningNonceError("This nonce was not issued to you.");
  if (row.purpose !== input.purpose) throw new SigningNonceError("This nonce was issued for a different action.");
  if ((input.transactionId ?? null) !== (row.transactionId ?? null)) {
    throw new SigningNonceError("This nonce was issued for a different transaction.");
  }
  if (row.used) throw new SigningNonceError("This nonce has already been used — call prepare again.");
  if (row.expiresAt.getTime() < Date.now()) {
    throw new SigningNonceError("This nonce has expired — call prepare again.");
  }

  await db.signingNonce.update({
    where: { nonce: input.nonce },
    data: { used: true, usedAt: new Date() },
  });

  return { payload: row.payload, payloadHash: row.payloadHash };
}
