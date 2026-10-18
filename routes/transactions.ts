// routes/transactions.ts
//
// Every signing step (transaction creation by the Landowner, approval by
// the Village Officer, approval by the Registrar) follows the same
// prepare -> sign -> submit shape:
//   POST .../prepare — the server validates everything it can up front,
//     builds the exact canonical string that must be signed, and freezes
//     it under a single-use nonce (lib/signingNonce.ts).
//   (the browser signs those exact bytes with the user's own private key,
//     unwrapped client-side — see frontend/src/lib/clientCrypto.ts; the
//     server never sees that key.)
//   POST .../submit — the browser sends back only {nonce, signatureValue}.
//     The server looks up the frozen payload by nonce (never trusting a
//     client-echoed payload), re-checks certificate validity and business
//     preconditions, verifies the signature against the actor's current
//     public key, and only then commits the Signature + business write +
//     audit entry in one transaction.
// A REJECT decision never involves a signature, so it stays a plain
// synchronous endpoint.

import express from "express";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { prisma } from "../lib/prisma.ts";
import { requireAuth, requireRole, requireCertifiedRole } from "../middleware/auth.ts";
import { verifySignature, verifySignatureOverCanonicalString } from "../lib/signing.ts";
import { verifyCertificate, verifyCertificateForUser, publicKeyPemFromCertificatePem, revokeCertificateTx } from "../lib/ca.ts";
import { createSigningNonce, consumeSigningNonce, SigningNonceError } from "../lib/signingNonce.ts";
import { canonicalStringify } from "../lib/canonicalize.ts";
import { appendAuditEntryTx, findSignatureAcceptedAt } from "../lib/audit.ts";
import { anchorAuditChainBestEffort } from "../lib/timestamp.ts";
import type { TransactionType } from "../generated/prisma/enums.ts";
import type { TransactionModel, LandRecordModel, SignatureModel } from "../generated/prisma/models.ts";

// Every business-write transaction below also writes an audit entry
// (appendAuditEntryTx, lib/audit.ts), which needs its own round trips on
// top of the business write's — against a remote Neon instance that adds
// up to more than Prisma's default 5s interactive-transaction timeout
// (observed directly: a single, uncontended submit took ~5.8s end to end).
// This isn't lock contention (that's lib/audit.ts's concern, documented
// there) — it's that several sequential awaited queries in one
// transaction, each a network round trip, cost more than 5s against this
// specific remote database. Same fix as lib/audit.ts: give it headroom.
const TRANSACTION_OPTIONS = { maxWait: 15_000, timeout: 15_000 };

// The actor relation on a signature is deliberately narrowed at the query
// level (see transactionWithChain) to never pull passwordHash or wrapped
// key material. certificateFingerprint comes along in the same query so
// verifySignatureChain stays synchronous (no per-signer DB round trip).
interface ActorSummary {
  id: string;
  name: string;
  publicKey: string;
  certificate: { fingerprint: string; certificatePem: string } | null;
}

const router = express.Router();

const UPLOAD_DIR = path.resolve(process.cwd(), "uploads");
const VALID_TYPES: TransactionType[] = ["REGISTRATION", "TRANSFER", "UPDATE", "SUCCESSION"];

// Checked before accepting ANY signature from `userId` — at creation and at
// every review stage, for both the actor signing right now and every prior
// signer already on the chain. A cryptographically valid RSA signature is
// not enough on its own: the signer's certificate must also not be expired
// or revoked at the moment we rely on it. Returns null when the actor's
// certificate is currently trustworthy; otherwise a human-readable reason
// to surface directly in the 403 response.
async function certificateProblem(userId: string): Promise<string | null> {
  const result = await verifyCertificateForUser(userId);
  if (!result) return "No certificate found for this user.";
  if (!result.valid) return result.details.reason ?? "Certificate is not valid.";
  return null;
}

async function requireCertificateFingerprint(userId: string): Promise<string> {
  const cert = await prisma.certificate.findUnique({ where: { subjectUserId: userId } });
  if (!cert) throw new Error(`No certificate on file for user ${userId}`);
  return cert.fingerprint;
}

// Every signature check below takes its public key from the actor's X.509
// certificate (parsed on demand), never from the User.publicKey column
// directly — the certificate is the thing that was actually signed and
// chained, so it's the authoritative source. Returns null exactly when
// `actor.certificate` is null (no certificate on file), the same
// null-safety verifySignatureChain() below already applies via its
// fingerprint check.
function actorPublicKeyPem(actor: ActorSummary): string | null {
  if (!actor.certificate) return null;
  return publicKeyPemFromCertificatePem(actor.certificate.certificatePem);
}

// Exported so the transaction payload can be rebuilt identically outside
// this route (e.g. a verification script) without duplicating field order
// or shape — verifySignature() only succeeds if this exact shape is reused.
// certificateFingerprint binds the signature to the exact certificate the
// signer held at signing time, not just whatever public key happens to be
// on their User row later — if a certificate were ever reissued, a
// signature made under the old one would no longer silently re-verify
// just because the new public key still decrypts *some* valid signature.
export interface TransactionPayload {
  type: string;
  landRecordId: string;
  fromOwnerId: string | null;
  toOwnerId: string;
  documentPath: string;
  documentHash: string;
  // SUCCESSION's optional heir/legal document — null for every other type
  // and whenever a SUCCESSION claim omits it. Included in the signed
  // payload for the same reason documentHash is: so it can't be swapped
  // out after the heir signs without invalidating their signature.
  secondaryDocumentPath: string | null;
  secondaryDocumentHash: string | null;
  actorId: string;
  certificateFingerprint: string;
  createdAt: string;
}

export function buildTransactionPayload(
  fields: TransactionPayload,
): TransactionPayload {
  return { ...fields };
}

// A review-stage signature (Village Officer or Registrar) signs its own
// payload chained to every signature that came before it by embedding the
// actual signatureValue bytes (not a hash/reference) of each prior
// signature, in chain order. Embedding the real RSA signature bytes — not
// a derived digest — means this stage's signature is a direct
// cryptographic commitment to "I signed after seeing exactly these prior
// signature bytes"; a spliced-in signature from a different transaction
// cannot be substituted without changing what's embedded here, which would
// break this signature's own verification. It also re-embeds the
// transaction's core immutable fields directly, so that tampering with the
// Transaction row itself (e.g. documentHash) invalidates every signature
// in the chain when reverified, not just the one that first captured it.
export interface ReviewPayload {
  transactionId: string;
  type: string;
  landRecordId: string;
  fromOwnerId: string | null;
  toOwnerId: string;
  documentPath: string;
  documentHash: string;
  secondaryDocumentPath: string | null;
  secondaryDocumentHash: string | null;
  priorSignatures: string[];
  actorId: string;
  role: string;
  certificateFingerprint: string;
  reviewedAt: string;
}

export function buildReviewPayload(fields: ReviewPayload): ReviewPayload {
  return { ...fields };
}

// Shared include shape: every review step needs the land record plus every
// signature so far, with each signature's actor. GET /pending-vo and
// GET /pending-registrar return these transactions to the client as-is, so
// the actor is deliberately `select`-ed down to exactly what verification/
// display needs — never passwordHash or wrapped key material.
const transactionWithChain = {
  landRecord: true,
  signatures: {
    orderBy: { signedAt: "asc" as const },
    include: {
      actor: {
        select: {
          id: true,
          name: true,
          publicKey: true,
          certificate: { select: { fingerprint: true, certificatePem: true } },
        },
      },
    },
  },
} as const;

export type TransactionWithChain = TransactionModel & {
  landRecord: LandRecordModel;
  signatures: (SignatureModel & { actor: ActorSummary })[];
};

function rebuildCreationPayload(
  transaction: Pick<
    TransactionModel,
    | "type"
    | "landRecordId"
    | "fromOwnerId"
    | "toOwnerId"
    | "documentPath"
    | "documentHash"
    | "secondaryDocumentPath"
    | "secondaryDocumentHash"
    | "createdAt"
  >,
  landownerActorId: string,
  certificateFingerprint: string,
) {
  return buildTransactionPayload({
    type: transaction.type,
    landRecordId: transaction.landRecordId,
    fromOwnerId: transaction.fromOwnerId,
    toOwnerId: transaction.toOwnerId,
    documentPath: transaction.documentPath,
    documentHash: transaction.documentHash,
    secondaryDocumentPath: transaction.secondaryDocumentPath,
    secondaryDocumentHash: transaction.secondaryDocumentHash,
    actorId: landownerActorId,
    certificateFingerprint,
    createdAt: transaction.createdAt.toISOString(),
  });
}

export interface SignatureChainResult {
  signatureId: string;
  actorId: string;
  actorName: string;
  role: string;
  signedAt: Date;
  valid: boolean;
}

// Only the fields the chain-rebuilding logic actually touches — deliberately
// narrower than TransactionWithChain so callers don't need to fetch (or
// type-satisfy) an unused `landRecord` relation just to call this.
type ChainableTransaction = Pick<
  TransactionModel,
  | "id"
  | "type"
  | "landRecordId"
  | "fromOwnerId"
  | "toOwnerId"
  | "documentPath"
  | "documentHash"
  | "secondaryDocumentPath"
  | "secondaryDocumentHash"
  | "createdAt"
> & {
  signatures: (SignatureModel & { actor: ActorSummary })[];
};

// Shared by the history endpoint (routes/land-records.ts) and the
// standalone verify endpoint below — one place that knows how to rebuild
// and live-verify every signature in a transaction's chain, so both
// callers can never drift out of sync with how signing actually works.
export function verifySignatureChain(transaction: ChainableTransaction): SignatureChainResult[] {
  return transaction.signatures.map((signature, index) => {
    // A signer with no certificate on file now can never re-verify — the
    // payload they signed embedded a fingerprint that can't be
    // reconstructed without one.
    const fingerprint = signature.actor.certificate?.fingerprint ?? null;

    // The chain always starts with the landowner's creation signature;
    // every signature after it is a review chained to every prior one.
    const payload =
      fingerprint === null
        ? null
        : signature.role === "LANDOWNER"
          ? buildTransactionPayload({
              type: transaction.type,
              landRecordId: transaction.landRecordId,
              fromOwnerId: transaction.fromOwnerId,
              toOwnerId: transaction.toOwnerId,
              documentPath: transaction.documentPath,
              documentHash: transaction.documentHash,
              secondaryDocumentPath: transaction.secondaryDocumentPath,
              secondaryDocumentHash: transaction.secondaryDocumentHash,
              actorId: signature.actorId,
              certificateFingerprint: fingerprint,
              createdAt: transaction.createdAt.toISOString(),
            })
          : buildReviewPayload({
              transactionId: transaction.id,
              type: transaction.type,
              landRecordId: transaction.landRecordId,
              fromOwnerId: transaction.fromOwnerId,
              toOwnerId: transaction.toOwnerId,
              documentPath: transaction.documentPath,
              documentHash: transaction.documentHash,
              secondaryDocumentPath: transaction.secondaryDocumentPath,
              secondaryDocumentHash: transaction.secondaryDocumentHash,
              priorSignatures: transaction.signatures
                .slice(0, index)
                .map((s) => s.signatureValue),
              actorId: signature.actorId,
              role: signature.role,
              certificateFingerprint: fingerprint,
              reviewedAt: signature.signedAt.toISOString(),
            });

    const actorKey = actorPublicKeyPem(signature.actor);
    const valid =
      payload !== null && actorKey !== null && verifySignature(actorKey, payload, signature.signatureValue);

    return {
      signatureId: signature.id,
      actorId: signature.actorId,
      actorName: signature.actor.name,
      role: signature.role,
      signedAt: signature.signedAt,
      valid, // live check, not the cached `valid` column
    };
  });
}

export interface DocumentIntegrityResult {
  match: boolean;
  error?: string;
}

// Shared by the standalone verify endpoint and the history endpoint —
// independently re-reads the file a transaction references and recomputes
// its SHA-256, rather than trusting the documentHash column. This is the
// other half of tamper-evidence alongside verifySignatureChain: a DB-level
// tamper of documentHash (see routes/dev.ts) breaks this check directly,
// on top of cascading into every signature that embeds documentHash.
async function checkOneDocument(documentPath: string, documentHash: string): Promise<DocumentIntegrityResult> {
  const resolvedDocumentPath = path.resolve(process.cwd(), documentPath);
  if (
    resolvedDocumentPath !== UPLOAD_DIR &&
    !resolvedDocumentPath.startsWith(UPLOAD_DIR + path.sep)
  ) {
    return { match: false, error: "documentPath is outside uploads/" };
  }

  try {
    const fileBuffer = await fs.promises.readFile(resolvedDocumentPath);
    const actualHash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
    return { match: actualHash === documentHash };
  } catch {
    return { match: false, error: "No file found at documentPath" };
  }
}

// Also checks the optional secondary document (SUCCESSION's heir/legal
// document) when present, so a tamper of either file is caught — not just
// the main document (the death certificate, for SUCCESSION).
export async function checkDocumentIntegrity(transaction: {
  documentPath: string;
  documentHash: string;
  secondaryDocumentPath?: string | null;
  secondaryDocumentHash?: string | null;
}): Promise<DocumentIntegrityResult> {
  const primary = await checkOneDocument(transaction.documentPath, transaction.documentHash);
  if (!primary.match) return primary;
  if (!transaction.secondaryDocumentPath || !transaction.secondaryDocumentHash) return primary;

  const secondary = await checkOneDocument(transaction.secondaryDocumentPath, transaction.secondaryDocumentHash);
  if (!secondary.match) {
    return { match: false, error: secondary.error ?? "Secondary document hash does not match what was recorded." };
  }
  return { match: true };
}

function handleSigningNonceError(err: unknown, res: express.Response): boolean {
  if (err instanceof SigningNonceError) {
    res.status(409).json({ error: err.message });
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Stage 1: Landowner creates the transaction.
// ---------------------------------------------------------------------------

interface PreparedCreatePayload {
  payload: TransactionPayload;
  canonical: string;
  landRecordId: string;
  resolvedToOwnerId: string;
  fromOwnerId: string | null;
  documentPath: string;
  documentHash: string;
  secondaryDocumentPath: string | null;
  secondaryDocumentHash: string | null;
  type: TransactionType;
}

async function validateOptionalSecondaryDocument(
  secondaryDocumentPath: unknown,
  secondaryDocumentHash: unknown,
  res: express.Response,
): Promise<{ ok: true; path: string | null; hash: string | null } | { ok: false }> {
  if (secondaryDocumentPath === undefined && secondaryDocumentHash === undefined) {
    return { ok: true, path: null, hash: null };
  }
  if (typeof secondaryDocumentPath !== "string" || !secondaryDocumentPath.trim()) {
    res.status(400).json({ error: "secondaryDocumentPath, if provided, must be a non-empty string" });
    return { ok: false };
  }
  if (typeof secondaryDocumentHash !== "string" || !/^[0-9a-f]{64}$/i.test(secondaryDocumentHash)) {
    res.status(400).json({ error: "secondaryDocumentHash, if provided, must be a 64-character hex SHA-256 hash" });
    return { ok: false };
  }
  const resolved = path.resolve(process.cwd(), secondaryDocumentPath);
  if (resolved !== UPLOAD_DIR && !resolved.startsWith(UPLOAD_DIR + path.sep)) {
    res.status(400).json({ error: "secondaryDocumentPath must reference a file under uploads/" });
    return { ok: false };
  }
  let fileBuffer: Buffer;
  try {
    fileBuffer = await fs.promises.readFile(resolved);
  } catch {
    res.status(400).json({ error: "No file found at secondaryDocumentPath" });
    return { ok: false };
  }
  const actualHash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
  if (actualHash !== secondaryDocumentHash) {
    res.status(400).json({ error: "Secondary document hash mismatch — possible tampering or corrupted upload" });
    return { ok: false };
  }
  return { ok: true, path: secondaryDocumentPath, hash: secondaryDocumentHash };
}

// Shared by prepare and submit so the two can never validate differently —
// submit re-runs every one of these checks against current DB state rather
// than trusting that nothing changed since prepare.
async function validateAndBuildCreatePayload(
  req: express.Request,
  res: express.Response,
): Promise<PreparedCreatePayload | null> {
  const { type, landRecordId, toOwnerId, documentPath, documentHash, secondaryDocumentPath, secondaryDocumentHash } =
    req.body ?? {};

  if (typeof type !== "string" || !VALID_TYPES.includes(type as TransactionType)) {
    res.status(400).json({ error: `type must be one of ${VALID_TYPES.join(", ")}` });
    return null;
  }
  if (typeof landRecordId !== "string" || !landRecordId.trim()) {
    res.status(400).json({ error: "landRecordId is required" });
    return null;
  }
  if (typeof documentPath !== "string" || !documentPath.trim()) {
    res.status(400).json({ error: "documentPath is required (from POST /api/documents/upload)" });
    return null;
  }
  if (typeof documentHash !== "string" || !/^[0-9a-f]{64}$/i.test(documentHash)) {
    res.status(400).json({ error: "documentHash must be a 64-character hex SHA-256 hash" });
    return null;
  }

  const resolvedDocumentPath = path.resolve(process.cwd(), documentPath);
  if (
    resolvedDocumentPath !== UPLOAD_DIR &&
    !resolvedDocumentPath.startsWith(UPLOAD_DIR + path.sep)
  ) {
    res.status(400).json({ error: "documentPath must reference a file under uploads/" });
    return null;
  }

  let fileBuffer: Buffer;
  try {
    fileBuffer = await fs.promises.readFile(resolvedDocumentPath);
  } catch {
    res.status(400).json({ error: "No file found at documentPath" });
    return null;
  }

  const actualDocumentHash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
  if (actualDocumentHash !== documentHash) {
    res.status(400).json({ error: "Document hash mismatch — possible tampering or corrupted upload" });
    return null;
  }

  const landRecord = await prisma.landRecord.findUnique({ where: { id: landRecordId } });
  if (!landRecord) {
    res.status(404).json({ error: "landRecord not found" });
    return null;
  }

  const actorId = req.user!.userId;

  // SUCCESSION is the one type where the actor (the heir) is deliberately
  // NOT the current owner — every other type still requires it.
  if (type !== "SUCCESSION" && landRecord.currentOwnerId !== actorId) {
    res.status(403).json({ error: "You are not the current owner of this land record" });
    return null;
  }
  if (type === "SUCCESSION" && landRecord.currentOwnerId === actorId) {
    res.status(400).json({ error: "You already own this land record — a succession claim is for records you don't own" });
    return null;
  }

  // Double-sale guard — see migration add_pending_transaction_unique_index
  // for the DB-level backstop behind this application-level check. Applies
  // identically to a succession claim: a record already PENDING (for any
  // reason) cannot also be claimed.
  if (landRecord.status !== "ACTIVE") {
    res.status(409).json({
      error: `landRecord is not ACTIVE (current status: ${landRecord.status}) — it may already have a transaction pending review`,
    });
    return null;
  }
  const existingPending = await prisma.transaction.findFirst({
    where: { landRecordId, status: { in: ["PENDING_VO", "PENDING_REGISTRAR"] } },
  });
  if (existingPending) {
    res.status(409).json({ error: "A transaction is already pending review for this land record" });
    return null;
  }

  let fromOwnerId: string | null;
  let resolvedToOwnerId: string;

  if (type === "TRANSFER") {
    if (typeof toOwnerId !== "string" || !toOwnerId.trim()) {
      res.status(400).json({ error: "toOwnerId is required for TRANSFER transactions" });
      return null;
    }
    if (toOwnerId === actorId) {
      res.status(400).json({ error: "You cannot transfer a land record to yourself" });
      return null;
    }
    const newOwner = await prisma.user.findUnique({ where: { id: toOwnerId } });
    if (!newOwner) {
      res.status(400).json({ error: "toOwnerId does not reference an existing user" });
      return null;
    }
    if (newOwner.role !== "LANDOWNER") {
      res.status(400).json({ error: "The new owner must be a registered Landowner" });
      return null;
    }
    fromOwnerId = actorId;
    resolvedToOwnerId = toOwnerId;
  } else if (type === "SUCCESSION") {
    // The heir IS the signer (actorId) — requireCertifiedRole("LANDOWNER")
    // on the route already guarantees they're a registered Landowner, so
    // there's no separate "must be a Landowner" lookup needed here the way
    // TRANSFER's toOwnerId (a different person) requires one.
    fromOwnerId = landRecord.currentOwnerId;
    resolvedToOwnerId = actorId;
  } else {
    fromOwnerId = null;
    resolvedToOwnerId = actorId;
  }

  const secondaryDoc = await validateOptionalSecondaryDocument(secondaryDocumentPath, secondaryDocumentHash, res);
  if (!secondaryDoc.ok) return null;

  const certProblem = await certificateProblem(actorId);
  if (certProblem) {
    res.status(403).json({ error: `Cannot sign: ${certProblem}` });
    return null;
  }
  const certificateFingerprint = await requireCertificateFingerprint(actorId);

  const payload = buildTransactionPayload({
    type,
    landRecordId,
    fromOwnerId,
    toOwnerId: resolvedToOwnerId,
    documentPath,
    documentHash,
    secondaryDocumentPath: secondaryDoc.path,
    secondaryDocumentHash: secondaryDoc.hash,
    actorId,
    certificateFingerprint,
    createdAt: new Date().toISOString(),
  });

  return {
    payload,
    canonical: canonicalStringify(payload),
    landRecordId,
    resolvedToOwnerId,
    fromOwnerId,
    documentPath,
    documentHash,
    secondaryDocumentPath: secondaryDoc.path,
    secondaryDocumentHash: secondaryDoc.hash,
    type: type as TransactionType,
  };
}

// POST /api/transactions/prepare
router.post("/prepare", requireAuth, requireCertifiedRole("LANDOWNER"), async (req, res) => {
  const prepared = await validateAndBuildCreatePayload(req, res);
  if (!prepared) return; // response already sent

  const nonceResult = await createSigningNonce({
    userId: req.user!.userId,
    purpose: "TRANSACTION_CREATE",
    canonicalPayload: prepared.canonical,
  });

  res.json(nonceResult);
});

// POST /api/transactions/submit
//
// Deliberately does NOT re-read type/landRecordId/documentPath/documentHash
// from req.body — a submit request only ever carries {nonce, signatureValue}.
// Every business fact (type, landRecordId, documentHash, etc.) comes from
// the FROZEN payload the nonce points to, i.e. the server's own prepare-time
// decision, never from whatever the client resends. Current-state
// preconditions (certificate validity, land record status) are re-checked
// here against that frozen payload's fields, because time has passed since
// prepare and either could have changed.
router.post("/submit", requireAuth, requireCertifiedRole("LANDOWNER"), async (req, res) => {
  const { nonce, signatureValue } = req.body ?? {};
  if (typeof nonce !== "string" || !nonce.trim()) {
    res.status(400).json({ error: "nonce is required" });
    return;
  }
  if (typeof signatureValue !== "string" || !signatureValue.trim()) {
    res.status(400).json({ error: "signatureValue is required" });
    return;
  }

  const actorId = req.user!.userId;
  const actor = await prisma.user.findUnique({
    where: { id: actorId },
    include: { certificate: { select: { certificatePem: true } } },
  });
  if (!actor) {
    res.status(401).json({ error: "Acting user no longer exists" });
    return;
  }

  try {
    const result = await prisma.$transaction(async (db) => {
      const { payload: frozenPayload } = await consumeSigningNonce(db, {
        nonce,
        userId: actorId,
        purpose: "TRANSACTION_CREATE",
        transactionId: null,
      });
      const parsed = JSON.parse(frozenPayload) as TransactionPayload;

      const certProblem = await certificateProblem(actorId);
      if (certProblem) {
        throw new SigningNonceError(`Cannot sign: ${certProblem}`);
      }

      const landRecord = await db.landRecord.findUnique({ where: { id: parsed.landRecordId } });
      if (!landRecord) {
        throw new SigningNonceError("landRecord no longer exists");
      }
      if (landRecord.status !== "ACTIVE") {
        throw new SigningNonceError(
          `landRecord is not ACTIVE (current status: ${landRecord.status}) — it may already have a transaction pending review`,
        );
      }

      // Re-checked here too, not just at prepare time — same reasoning as
      // every other precondition in this block: time has passed since
      // prepare, and the frozen payload's toOwnerId could in principle no
      // longer satisfy these rules even though it couldn't have been
      // forged (consumeSigningNonce already ties it to this exact actor).
      if (parsed.type === "TRANSFER") {
        if (parsed.toOwnerId === actorId) {
          throw new SigningNonceError("You cannot transfer a land record to yourself");
        }
        const newOwner = await db.user.findUnique({ where: { id: parsed.toOwnerId } });
        if (!newOwner || newOwner.role !== "LANDOWNER") {
          throw new SigningNonceError("The new owner must be a registered Landowner");
        }
      }
      if (parsed.type === "SUCCESSION" && landRecord.currentOwnerId === actorId) {
        throw new SigningNonceError("You already own this land record — a succession claim is for records you don't own");
      }

      const actorKeyPem = actor.certificate ? publicKeyPemFromCertificatePem(actor.certificate.certificatePem) : null;
      if (!actorKeyPem) {
        throw new SigningNonceError("No certificate on file for this account.");
      }
      const signatureValid = verifySignatureOverCanonicalString(
        actorKeyPem,
        frozenPayload,
        signatureValue,
      );
      if (!signatureValid) {
        throw new SigningNonceError("Signature does not match the prepared payload.");
      }

      const dataHash = crypto.createHash("sha256").update(frozenPayload, "utf8").digest("hex");
      const createdAt = new Date(parsed.createdAt);

      const transaction = await db.transaction.create({
        data: {
          type: parsed.type as TransactionType,
          landRecordId: parsed.landRecordId,
          fromOwnerId: parsed.fromOwnerId,
          toOwnerId: parsed.toOwnerId,
          documentPath: parsed.documentPath,
          documentHash: parsed.documentHash,
          secondaryDocumentPath: parsed.secondaryDocumentPath,
          secondaryDocumentHash: parsed.secondaryDocumentHash,
          status: "PENDING_VO",
          createdAt,
        },
      });

      const signature = await db.signature.create({
        data: {
          transactionId: transaction.id,
          actorId,
          role: actor.role,
          signatureValue,
          dataHash,
        },
      });

      await db.landRecord.update({
        where: { id: parsed.landRecordId },
        data: { status: "PENDING" },
      });

      await appendAuditEntryTx(db, {
        action: "TRANSACTION_CREATED",
        actorUserId: actorId,
        entityType: "TRANSACTION",
        entityId: transaction.id,
        details: { type: parsed.type, landRecordId: parsed.landRecordId, documentHash: parsed.documentHash },
      });

      return { transaction, signature };
    }, TRANSACTION_OPTIONS);

    res.status(201).json({ ...result.transaction, signature: result.signature });
  } catch (err: unknown) {
    if (handleSigningNonceError(err, res)) return;
    // P2002 via the partial unique index on (landRecordId) WHERE status IN
    // (PENDING_VO, PENDING_REGISTRAR) — the race-condition backstop behind
    // the landRecord.status check above.
    if (typeof err === "object" && err !== null && "code" in err && (err as { code?: string }).code === "P2002") {
      res.status(409).json({ error: "A transaction is already pending review for this land record" });
      return;
    }
    throw err;
  }
});

// GET /api/transactions/mine — every transaction where the caller is
// either the seller (fromOwnerId) or the buyer (toOwnerId), regardless of
// who currently owns the land record. Needed because GET /land-records is
// scoped to CURRENT ownership only: without this, a buyer has no way to
// see an incoming transfer before it's approved (they don't own the
// record yet), and a seller loses visibility of an outgoing transfer the
// moment it's approved (they no longer own the record either).
router.get("/mine", requireAuth, async (req, res) => {
  const userId = req.user!.userId;
  const transactions = await prisma.transaction.findMany({
    where: { OR: [{ fromOwnerId: userId }, { toOwnerId: userId }] },
    include: {
      landRecord: { select: { surveyNumber: true, location: true } },
      fromOwner: { select: { name: true } },
      toOwner: { select: { name: true } },
    },
    orderBy: { createdAt: "desc" },
  });

  res.json(
    transactions.map((t) => ({
      id: t.id,
      type: t.type,
      landRecordId: t.landRecordId,
      surveyNumber: t.landRecord.surveyNumber,
      location: t.landRecord.location,
      fromOwnerId: t.fromOwnerId,
      fromOwnerName: t.fromOwner?.name ?? null,
      toOwnerId: t.toOwnerId,
      toOwnerName: t.toOwner.name,
      status: t.status,
      rejectReason: t.rejectReason,
      createdAt: t.createdAt,
      isBuyer: t.toOwnerId === userId,
      isSeller: t.fromOwnerId === userId,
    })),
  );
});

// GET /api/transactions/pending-vo
router.get("/pending-vo", requireAuth, requireRole("VILLAGE_OFFICER"), async (_req, res) => {
  const transactions = await prisma.transaction.findMany({
    where: { status: "PENDING_VO" },
    include: transactionWithChain,
    orderBy: { createdAt: "asc" },
  });
  res.json(transactions);
});

// ---------------------------------------------------------------------------
// Stage 2: Village Officer review.
// ---------------------------------------------------------------------------

interface PriorCheckResult {
  ok: boolean;
  failureReason: string | null;
}

// Separation of duties: the SAME account (not just the same role — roles
// are one-per-account, so this only ever matters when one real person
// registers more than one account) may never sign a transaction at more
// than one stage. This single check covers both halves of that rule at
// once — "nobody reviews a transaction they created" is just the case
// where the prior stage being checked against is the LANDOWNER's own
// creation signature.
export function reviewerIsPriorSigner(reviewerId: string, transaction: TransactionWithChain): boolean {
  return transaction.signatures.some((s) => s.actorId === reviewerId);
}

async function checkLandownerSignatureValid(
  transaction: TransactionWithChain,
  landownerSignature: TransactionWithChain["signatures"][number],
): Promise<PriorCheckResult> {
  const fingerprint = landownerSignature.actor.certificate?.fingerprint;
  const landownerKey = actorPublicKeyPem(landownerSignature.actor);
  const landownerValid =
    fingerprint !== undefined &&
    fingerprint !== null &&
    landownerKey !== null &&
    verifySignature(
      landownerKey,
      rebuildCreationPayload(transaction, landownerSignature.actorId, fingerprint),
      landownerSignature.signatureValue,
    );
  if (!landownerValid) {
    return { ok: false, failureReason: "Landowner signature verification failed" };
  }
  const certProblem = await certificateProblem(landownerSignature.actorId);
  if (certProblem) {
    return { ok: false, failureReason: `Landowner certificate invalid: ${certProblem}` };
  }
  return { ok: true, failureReason: null };
}

async function autoRejectTransaction(
  transactionId: string,
  landRecordId: string,
  actorUserId: string,
  action: "VO_REVIEW" | "REGISTRAR_REVIEW",
  failureReason: string,
) {
  return prisma.$transaction(async (db) => {
    const txn = await db.transaction.update({
      where: { id: transactionId },
      data: { status: "REJECTED", rejectReason: failureReason },
    });
    await db.landRecord.update({ where: { id: landRecordId }, data: { status: "ACTIVE" } });
    await appendAuditEntryTx(db, {
      action,
      actorUserId,
      entityType: "TRANSACTION",
      entityId: transactionId,
      details: { decision: "AUTO_REJECTED", reason: failureReason },
    });
    return txn;
  }, TRANSACTION_OPTIONS);
}

// POST /api/transactions/:id/vo-review/reject
router.post("/:id/vo-review/reject", requireAuth, requireCertifiedRole("VILLAGE_OFFICER"), async (req, res) => {
  const { reason } = req.body ?? {};
  const transaction = await prisma.transaction.findUnique({
    where: { id: req.params.id },
    include: transactionWithChain,
  });
  if (!transaction) {
    res.status(404).json({ error: "Transaction not found" });
    return;
  }
  if (transaction.status !== "PENDING_VO") {
    res.status(400).json({ error: "Transaction is not pending Village Officer review" });
    return;
  }
  const landownerSignature = transaction.signatures.find((s) => s.role === "LANDOWNER");
  if (!landownerSignature) {
    res.status(500).json({ error: "Landowner signature missing on this transaction" });
    return;
  }
  if (reviewerIsPriorSigner(req.user!.userId, transaction)) {
    res.status(403).json({ error: "You cannot review a transaction you created." });
    return;
  }

  const priorCheck = await checkLandownerSignatureValid(transaction, landownerSignature);
  if (!priorCheck.ok) {
    const updated = await autoRejectTransaction(
      transaction.id,
      transaction.landRecordId,
      req.user!.userId,
      "VO_REVIEW",
      priorCheck.failureReason!,
    );
    res.status(200).json({ transaction: updated, autoRejected: true, reason: priorCheck.failureReason });
    return;
  }

  if (typeof reason !== "string" || !reason.trim()) {
    res.status(400).json({ error: "reason is required to reject" });
    return;
  }
  const updated = await prisma.$transaction(async (db) => {
    const txn = await db.transaction.update({
      where: { id: transaction.id },
      data: { status: "REJECTED", rejectReason: reason },
    });
    await db.landRecord.update({ where: { id: transaction.landRecordId }, data: { status: "ACTIVE" } });
    await appendAuditEntryTx(db, {
      action: "VO_REVIEW",
      actorUserId: req.user!.userId,
      entityType: "TRANSACTION",
      entityId: transaction.id,
      details: { decision: "REJECT", reason },
    });
    return txn;
  }, TRANSACTION_OPTIONS);
  res.json(updated);
});

// POST /api/transactions/:id/vo-review/prepare
router.post("/:id/vo-review/prepare", requireAuth, requireCertifiedRole("VILLAGE_OFFICER"), async (req, res) => {
  const transaction = await prisma.transaction.findUnique({
    where: { id: req.params.id },
    include: transactionWithChain,
  });
  if (!transaction) {
    res.status(404).json({ error: "Transaction not found" });
    return;
  }
  if (transaction.status !== "PENDING_VO") {
    res.status(400).json({ error: "Transaction is not pending Village Officer review" });
    return;
  }
  const landownerSignature = transaction.signatures.find((s) => s.role === "LANDOWNER");
  if (!landownerSignature) {
    res.status(500).json({ error: "Landowner signature missing on this transaction" });
    return;
  }
  if (reviewerIsPriorSigner(req.user!.userId, transaction)) {
    res.status(403).json({ error: "You cannot review a transaction you created." });
    return;
  }

  const priorCheck = await checkLandownerSignatureValid(transaction, landownerSignature);
  if (!priorCheck.ok) {
    const updated = await autoRejectTransaction(
      transaction.id,
      transaction.landRecordId,
      req.user!.userId,
      "VO_REVIEW",
      priorCheck.failureReason!,
    );
    res.status(200).json({ transaction: updated, autoRejected: true, reason: priorCheck.failureReason });
    return;
  }

  const voId = req.user!.userId;
  const certProblem = await certificateProblem(voId);
  if (certProblem) {
    res.status(403).json({ error: `Cannot sign: ${certProblem}` });
    return;
  }
  const certificateFingerprint = await requireCertificateFingerprint(voId);

  const payload = buildReviewPayload({
    transactionId: transaction.id,
    type: transaction.type,
    landRecordId: transaction.landRecordId,
    fromOwnerId: transaction.fromOwnerId,
    toOwnerId: transaction.toOwnerId,
    documentPath: transaction.documentPath,
    documentHash: transaction.documentHash,
    secondaryDocumentPath: transaction.secondaryDocumentPath,
    secondaryDocumentHash: transaction.secondaryDocumentHash,
    priorSignatures: [landownerSignature.signatureValue],
    actorId: voId,
    role: "VILLAGE_OFFICER",
    certificateFingerprint,
    reviewedAt: new Date().toISOString(),
  });

  const prepared = await createSigningNonce({
    userId: voId,
    purpose: "VO_REVIEW_APPROVE",
    transactionId: transaction.id,
    canonicalPayload: canonicalStringify(payload),
  });

  res.json(prepared);
});

// POST /api/transactions/:id/vo-review/submit
router.post("/:id/vo-review/submit", requireAuth, requireCertifiedRole("VILLAGE_OFFICER"), async (req, res) => {
  const { nonce, signatureValue } = req.body ?? {};
  if (typeof nonce !== "string" || !nonce.trim() || typeof signatureValue !== "string" || !signatureValue.trim()) {
    res.status(400).json({ error: "nonce and signatureValue are required" });
    return;
  }

  const transaction = await prisma.transaction.findUnique({
    where: { id: req.params.id },
    include: transactionWithChain,
  });
  if (!transaction) {
    res.status(404).json({ error: "Transaction not found" });
    return;
  }
  if (transaction.status !== "PENDING_VO") {
    res.status(400).json({ error: "Transaction is not pending Village Officer review" });
    return;
  }
  const landownerSignature = transaction.signatures.find((s) => s.role === "LANDOWNER");
  if (!landownerSignature) {
    res.status(500).json({ error: "Landowner signature missing on this transaction" });
    return;
  }
  if (reviewerIsPriorSigner(req.user!.userId, transaction)) {
    res.status(403).json({ error: "You cannot review a transaction you created." });
    return;
  }

  // Re-check now, not just at prepare time — time has passed.
  const priorCheck = await checkLandownerSignatureValid(transaction, landownerSignature);
  if (!priorCheck.ok) {
    const updated = await autoRejectTransaction(
      transaction.id,
      transaction.landRecordId,
      req.user!.userId,
      "VO_REVIEW",
      priorCheck.failureReason!,
    );
    res.status(200).json({ transaction: updated, autoRejected: true, reason: priorCheck.failureReason });
    return;
  }

  const voId = req.user!.userId;
  const certProblem = await certificateProblem(voId);
  if (certProblem) {
    res.status(403).json({ error: `Cannot sign: ${certProblem}` });
    return;
  }
  const vo = await prisma.user.findUnique({
    where: { id: voId },
    include: { certificate: { select: { certificatePem: true } } },
  });
  if (!vo) {
    res.status(401).json({ error: "Acting user no longer exists" });
    return;
  }

  try {
    const result = await prisma.$transaction(async (db) => {
      const { payload: frozenPayload, payloadHash } = await consumeSigningNonce(db, {
        nonce,
        userId: voId,
        purpose: "VO_REVIEW_APPROVE",
        transactionId: transaction.id,
      });

      const voKeyPem = vo.certificate ? publicKeyPemFromCertificatePem(vo.certificate.certificatePem) : null;
      if (!voKeyPem) {
        throw new SigningNonceError("No certificate on file for this account.");
      }
      const signatureValid = verifySignatureOverCanonicalString(voKeyPem, frozenPayload, signatureValue);
      if (!signatureValid) {
        throw new SigningNonceError("Signature does not match the prepared payload.");
      }

      const reviewedAt = new Date((JSON.parse(frozenPayload) as ReviewPayload).reviewedAt);

      const txn = await db.transaction.update({
        where: { id: transaction.id },
        data: { status: "PENDING_REGISTRAR" },
      });
      const signature = await db.signature.create({
        data: {
          transactionId: transaction.id,
          actorId: voId,
          role: "VILLAGE_OFFICER",
          signatureValue,
          dataHash: payloadHash,
          signedAt: reviewedAt,
        },
      });
      await appendAuditEntryTx(db, {
        action: "VO_REVIEW",
        actorUserId: voId,
        entityType: "TRANSACTION",
        entityId: transaction.id,
        details: { decision: "APPROVE" },
      });
      return { txn, signature };
    }, TRANSACTION_OPTIONS);

    res.json({ ...result.txn, signature: result.signature });
  } catch (err: unknown) {
    if (handleSigningNonceError(err, res)) return;
    throw err;
  }
});

// GET /api/transactions/pending-registrar
router.get("/pending-registrar", requireAuth, requireRole("REGISTRAR"), async (_req, res) => {
  const transactions = await prisma.transaction.findMany({
    where: { status: "PENDING_REGISTRAR" },
    include: transactionWithChain,
    orderBy: { createdAt: "asc" },
  });
  res.json(transactions);
});

// ---------------------------------------------------------------------------
// Stage 3: Registrar review.
// ---------------------------------------------------------------------------

async function checkPriorSignaturesValidForRegistrar(
  transaction: TransactionWithChain,
  landownerSignature: TransactionWithChain["signatures"][number],
  voSignature: TransactionWithChain["signatures"][number],
): Promise<PriorCheckResult> {
  const landownerFingerprint = landownerSignature.actor.certificate?.fingerprint;
  const landownerKey = actorPublicKeyPem(landownerSignature.actor);
  const landownerValid =
    landownerFingerprint !== undefined &&
    landownerFingerprint !== null &&
    landownerKey !== null &&
    verifySignature(
      landownerKey,
      rebuildCreationPayload(transaction, landownerSignature.actorId, landownerFingerprint),
      landownerSignature.signatureValue,
    );

  const voFingerprint = voSignature.actor.certificate?.fingerprint;
  const voKey = actorPublicKeyPem(voSignature.actor);
  const voValid =
    voFingerprint !== undefined &&
    voFingerprint !== null &&
    voKey !== null &&
    verifySignature(
      voKey,
      buildReviewPayload({
        transactionId: transaction.id,
        type: transaction.type,
        landRecordId: transaction.landRecordId,
        fromOwnerId: transaction.fromOwnerId,
        toOwnerId: transaction.toOwnerId,
        documentPath: transaction.documentPath,
        documentHash: transaction.documentHash,
        secondaryDocumentPath: transaction.secondaryDocumentPath,
        secondaryDocumentHash: transaction.secondaryDocumentHash,
        priorSignatures: [landownerSignature.signatureValue],
        actorId: voSignature.actorId,
        role: "VILLAGE_OFFICER",
        certificateFingerprint: voFingerprint,
        reviewedAt: voSignature.signedAt.toISOString(),
      }),
      voSignature.signatureValue,
    );

  const landownerCertProblem = landownerValid ? await certificateProblem(landownerSignature.actorId) : null;
  const voCertProblem = voValid ? await certificateProblem(voSignature.actorId) : null;

  if (!landownerValid || !voValid || landownerCertProblem || voCertProblem) {
    const problems: string[] = [];
    if (!landownerValid) problems.push("Landowner signature verification failed");
    else if (landownerCertProblem) problems.push(`Landowner certificate invalid: ${landownerCertProblem}`);
    if (!voValid) problems.push("Village Officer signature verification failed");
    else if (voCertProblem) problems.push(`Village Officer certificate invalid: ${voCertProblem}`);
    return { ok: false, failureReason: problems.join("; ") };
  }
  return { ok: true, failureReason: null };
}

// POST /api/transactions/:id/registrar-review/reject
router.post("/:id/registrar-review/reject", requireAuth, requireCertifiedRole("REGISTRAR"), async (req, res) => {
  const { reason } = req.body ?? {};
  const transaction = await prisma.transaction.findUnique({
    where: { id: req.params.id },
    include: transactionWithChain,
  });
  if (!transaction) {
    res.status(404).json({ error: "Transaction not found" });
    return;
  }
  if (transaction.status !== "PENDING_REGISTRAR") {
    res.status(400).json({ error: "Transaction is not pending Registrar review" });
    return;
  }
  const landownerSignature = transaction.signatures.find((s) => s.role === "LANDOWNER");
  const voSignature = transaction.signatures.find((s) => s.role === "VILLAGE_OFFICER");
  if (!landownerSignature || !voSignature) {
    res.status(500).json({ error: "Signature chain is incomplete on this transaction" });
    return;
  }
  if (reviewerIsPriorSigner(req.user!.userId, transaction)) {
    res.status(403).json({
      error: "You cannot review this transaction — you already signed it at an earlier stage, or created it.",
    });
    return;
  }

  const priorCheck = await checkPriorSignaturesValidForRegistrar(transaction, landownerSignature, voSignature);
  if (!priorCheck.ok) {
    const updated = await autoRejectTransaction(
      transaction.id,
      transaction.landRecordId,
      req.user!.userId,
      "REGISTRAR_REVIEW",
      priorCheck.failureReason!,
    );
    res.status(200).json({ transaction: updated, autoRejected: true, reason: priorCheck.failureReason });
    return;
  }

  if (typeof reason !== "string" || !reason.trim()) {
    res.status(400).json({ error: "reason is required to reject" });
    return;
  }
  const updated = await prisma.$transaction(async (db) => {
    const txn = await db.transaction.update({
      where: { id: transaction.id },
      data: { status: "REJECTED", rejectReason: reason },
    });
    await db.landRecord.update({ where: { id: transaction.landRecordId }, data: { status: "ACTIVE" } });
    await appendAuditEntryTx(db, {
      action: "REGISTRAR_REVIEW",
      actorUserId: req.user!.userId,
      entityType: "TRANSACTION",
      entityId: transaction.id,
      details: { decision: "REJECT", reason },
    });
    return txn;
  }, TRANSACTION_OPTIONS);
  res.json(updated);
  // Fire-and-forget, after the response is already sent: a transaction
  // reaching its final Registrar decision (reject, here) is a natural
  // anchor point, but the TSA round trip must never add latency to this
  // request or fail it — anchorAuditChainBestEffort() never throws and
  // only ever logs a short warning on failure.
  anchorAuditChainBestEffort();
});

// POST /api/transactions/:id/registrar-review/prepare
router.post("/:id/registrar-review/prepare", requireAuth, requireCertifiedRole("REGISTRAR"), async (req, res) => {
  const transaction = await prisma.transaction.findUnique({
    where: { id: req.params.id },
    include: transactionWithChain,
  });
  if (!transaction) {
    res.status(404).json({ error: "Transaction not found" });
    return;
  }
  if (transaction.status !== "PENDING_REGISTRAR") {
    res.status(400).json({ error: "Transaction is not pending Registrar review" });
    return;
  }
  const landownerSignature = transaction.signatures.find((s) => s.role === "LANDOWNER");
  const voSignature = transaction.signatures.find((s) => s.role === "VILLAGE_OFFICER");
  if (!landownerSignature || !voSignature) {
    res.status(500).json({ error: "Signature chain is incomplete on this transaction" });
    return;
  }
  if (reviewerIsPriorSigner(req.user!.userId, transaction)) {
    res.status(403).json({
      error: "You cannot review this transaction — you already signed it at an earlier stage, or created it.",
    });
    return;
  }

  const priorCheck = await checkPriorSignaturesValidForRegistrar(transaction, landownerSignature, voSignature);
  if (!priorCheck.ok) {
    const updated = await autoRejectTransaction(
      transaction.id,
      transaction.landRecordId,
      req.user!.userId,
      "REGISTRAR_REVIEW",
      priorCheck.failureReason!,
    );
    res.status(200).json({ transaction: updated, autoRejected: true, reason: priorCheck.failureReason });
    return;
  }

  const registrarId = req.user!.userId;
  const certProblem = await certificateProblem(registrarId);
  if (certProblem) {
    res.status(403).json({ error: `Cannot sign: ${certProblem}` });
    return;
  }
  const certificateFingerprint = await requireCertificateFingerprint(registrarId);

  const payload = buildReviewPayload({
    transactionId: transaction.id,
    type: transaction.type,
    landRecordId: transaction.landRecordId,
    fromOwnerId: transaction.fromOwnerId,
    toOwnerId: transaction.toOwnerId,
    documentPath: transaction.documentPath,
    documentHash: transaction.documentHash,
    secondaryDocumentPath: transaction.secondaryDocumentPath,
    secondaryDocumentHash: transaction.secondaryDocumentHash,
    priorSignatures: [landownerSignature.signatureValue, voSignature.signatureValue],
    actorId: registrarId,
    role: "REGISTRAR",
    certificateFingerprint,
    reviewedAt: new Date().toISOString(),
  });

  const prepared = await createSigningNonce({
    userId: registrarId,
    purpose: "REGISTRAR_REVIEW_APPROVE",
    transactionId: transaction.id,
    canonicalPayload: canonicalStringify(payload),
  });

  res.json(prepared);
});

// POST /api/transactions/:id/registrar-review/submit
router.post("/:id/registrar-review/submit", requireAuth, requireCertifiedRole("REGISTRAR"), async (req, res) => {
  const { nonce, signatureValue } = req.body ?? {};
  if (typeof nonce !== "string" || !nonce.trim() || typeof signatureValue !== "string" || !signatureValue.trim()) {
    res.status(400).json({ error: "nonce and signatureValue are required" });
    return;
  }

  const transaction = await prisma.transaction.findUnique({
    where: { id: req.params.id },
    include: transactionWithChain,
  });
  if (!transaction) {
    res.status(404).json({ error: "Transaction not found" });
    return;
  }
  if (transaction.status !== "PENDING_REGISTRAR") {
    res.status(400).json({ error: "Transaction is not pending Registrar review" });
    return;
  }
  const landownerSignature = transaction.signatures.find((s) => s.role === "LANDOWNER");
  const voSignature = transaction.signatures.find((s) => s.role === "VILLAGE_OFFICER");
  if (!landownerSignature || !voSignature) {
    res.status(500).json({ error: "Signature chain is incomplete on this transaction" });
    return;
  }
  if (reviewerIsPriorSigner(req.user!.userId, transaction)) {
    res.status(403).json({
      error: "You cannot review this transaction — you already signed it at an earlier stage, or created it.",
    });
    return;
  }

  const priorCheck = await checkPriorSignaturesValidForRegistrar(transaction, landownerSignature, voSignature);
  if (!priorCheck.ok) {
    const updated = await autoRejectTransaction(
      transaction.id,
      transaction.landRecordId,
      req.user!.userId,
      "REGISTRAR_REVIEW",
      priorCheck.failureReason!,
    );
    res.status(200).json({ transaction: updated, autoRejected: true, reason: priorCheck.failureReason });
    return;
  }

  const registrarId = req.user!.userId;
  const certProblem = await certificateProblem(registrarId);
  if (certProblem) {
    res.status(403).json({ error: `Cannot sign: ${certProblem}` });
    return;
  }
  const registrar = await prisma.user.findUnique({
    where: { id: registrarId },
    include: { certificate: { select: { certificatePem: true } } },
  });
  if (!registrar) {
    res.status(401).json({ error: "Acting user no longer exists" });
    return;
  }

  try {
    const result = await prisma.$transaction(async (db) => {
      const { payload: frozenPayload, payloadHash } = await consumeSigningNonce(db, {
        nonce,
        userId: registrarId,
        purpose: "REGISTRAR_REVIEW_APPROVE",
        transactionId: transaction.id,
      });

      const registrarKeyPem = registrar.certificate
        ? publicKeyPemFromCertificatePem(registrar.certificate.certificatePem)
        : null;
      if (!registrarKeyPem) {
        throw new SigningNonceError("No certificate on file for this account.");
      }
      const signatureValid = verifySignatureOverCanonicalString(registrarKeyPem, frozenPayload, signatureValue);
      if (!signatureValid) {
        throw new SigningNonceError("Signature does not match the prepared payload.");
      }

      const reviewedAt = new Date((JSON.parse(frozenPayload) as ReviewPayload).reviewedAt);

      const txn = await db.transaction.update({
        where: { id: transaction.id },
        data: { status: "APPROVED" },
      });
      const signature = await db.signature.create({
        data: {
          transactionId: transaction.id,
          actorId: registrarId,
          role: "REGISTRAR",
          signatureValue,
          dataHash: payloadHash,
          signedAt: reviewedAt,
        },
      });

      const landRecordUpdate: { status: "ACTIVE"; currentOwnerId?: string } = { status: "ACTIVE" };
      if (transaction.type === "REGISTRATION" || transaction.type === "TRANSFER" || transaction.type === "SUCCESSION") {
        landRecordUpdate.currentOwnerId = transaction.toOwnerId;
      }
      const landRecord = await db.landRecord.update({
        where: { id: transaction.landRecordId },
        data: landRecordUpdate,
      });

      await appendAuditEntryTx(db, {
        action: "REGISTRAR_REVIEW",
        actorUserId: registrarId,
        entityType: "TRANSACTION",
        entityId: transaction.id,
        details: { decision: "APPROVE" },
      });

      // SUCCESSION's whole point: everything below happens atomically with
      // the ownership change above — the deceased's account is retired and
      // every OTHER transaction of theirs still in flight is cancelled, so
      // the system can never be left with a "deceased" owner who still
      // looks fully active everywhere except this one record.
      if (transaction.type === "SUCCESSION" && transaction.fromOwnerId) {
        const deceasedId = transaction.fromOwnerId;

        const deceasedCert = await db.certificate.findUnique({ where: { subjectUserId: deceasedId } });
        if (deceasedCert && !deceasedCert.revoked) {
          await revokeCertificateTx(db, {
            certificateId: deceasedCert.id,
            revokedByUserId: registrarId,
            reason: "Owner deceased",
          });
        }

        await db.user.update({ where: { id: deceasedId }, data: { status: "DECEASED" } });
        await appendAuditEntryTx(db, {
          action: "USER_MARKED_DECEASED",
          actorUserId: registrarId,
          entityType: "USER",
          entityId: deceasedId,
          details: { succeededByUserId: transaction.toOwnerId, transactionId: transaction.id },
        });

        const otherPending = await db.transaction.findMany({
          where: {
            id: { not: transaction.id },
            status: { in: ["PENDING_VO", "PENDING_REGISTRAR"] },
            OR: [{ fromOwnerId: deceasedId }, { toOwnerId: deceasedId }],
          },
        });
        for (const other of otherPending) {
          await db.transaction.update({
            where: { id: other.id },
            data: { status: "REJECTED", rejectReason: "Cancelled — owner deceased" },
          });
          await db.landRecord.update({ where: { id: other.landRecordId }, data: { status: "ACTIVE" } });
          await appendAuditEntryTx(db, {
            action: "TRANSACTION_CANCELLED",
            actorUserId: registrarId,
            entityType: "TRANSACTION",
            entityId: other.id,
            details: { reason: "Owner deceased", deceasedUserId: deceasedId },
          });
        }
      }

      return { txn, signature, landRecord };
    }, TRANSACTION_OPTIONS);

    res.json({ ...result.txn, signature: result.signature, landRecord: result.landRecord });
    // Same reasoning as the reject route above: fire-and-forget, after the
    // response, never allowed to add latency or fail this request.
    anchorAuditChainBestEffort();
  } catch (err: unknown) {
    if (handleSigningNonceError(err, res)) return;
    throw err;
  }
});

// ---------------------------------------------------------------------------
// Standalone verification tool (case study §6.5) — deliberately independent
// of the approval workflow above. Works for a transaction in ANY status,
// pending or already decided: it's a diagnostic "prove this is genuine"
// check, not a step that moves a transaction forward.
// ---------------------------------------------------------------------------

// GET /api/transactions/:id/verify
router.get("/:id/verify", requireAuth, async (req, res) => {
  const transaction = await prisma.transaction.findUnique({
    where: { id: req.params.id },
    include: transactionWithChain,
  });

  if (!transaction) {
    res.status(404).json({ error: "Transaction not found" });
    return;
  }

  // signerIdentity + signatureValidity share the same chain walk.
  const chain = verifySignatureChain(transaction);

  // certificateValid below answers "was this signer's certificate valid AT
  // THE MOMENT they signed" — not "is it valid right now" — so a
  // certificate revoked later (e.g. the owner in a SUCCESSION claim,
  // revoked on final approval) doesn't retroactively invalidate a
  // signature that was genuine when it was made. The "as of" timestamp
  // comes only from the hash-chained audit log (findSignatureAcceptedAt,
  // lib/audit.ts) — never the Signature row's own signedAt column, which
  // isn't independently tamper-evident the same way.
  const signerIdentity = await Promise.all(
    chain.map(async (link) => {
      const certificate = await prisma.certificate.findUnique({
        where: { subjectUserId: link.actorId },
      });
      if (!certificate) {
        return {
          actorId: link.actorId,
          actorName: link.actorName,
          role: link.role,
          certificateValid: false,
          certificateReason: "No certificate found for this user.",
          currentlyRevoked: false,
          currentlyRevokedReason: null,
          signingTimeTrusted: false,
        };
      }

      const acceptedAt = await findSignatureAcceptedAt(transaction.id, link.actorId, link.role);
      const trusted = acceptedAt !== null;
      const asOfResult = await verifyCertificate(certificate.id, acceptedAt ?? new Date());
      const nowResult = await verifyCertificate(certificate.id);

      return {
        actorId: link.actorId,
        actorName: link.actorName,
        role: link.role,
        // Untrusted (no matching audit entry — e.g. a signature row
        // inserted directly into the database, bypassing the API) is
        // never reported as valid, regardless of what asOfResult says.
        certificateValid: trusted && asOfResult.valid,
        certificateReason: trusted
          ? asOfResult.details.reason
          : "No matching audit log entry for this signature — its timestamp cannot be trusted.",
        currentlyRevoked: nowResult.details.revoked,
        currentlyRevokedReason: nowResult.details.revokedReason,
        signingTimeTrusted: trusted,
      };
    }),
  );

  const signatureValidity = chain.map((link) => ({
    actorName: link.actorName,
    role: link.role,
    signedAt: link.signedAt,
    valid: link.valid,
  }));

  // documentIntegrity: same independent re-hash used at transaction
  // creation time, re-run here on demand for a transaction in any status.
  const documentIntegrity = await checkDocumentIntegrity(transaction);

  res.json({
    transactionId: transaction.id,
    status: transaction.status,
    signerIdentity,
    signatureValidity,
    documentIntegrity,
  });
});

export default router;
