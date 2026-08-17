// routes/transactions.ts
//
// POST /api/transactions — Landowner-only. Builds a transaction payload,
// signs it with the acting landowner's own RSA private key (lib/signing.ts),
// and atomically creates the Transaction + Signature rows and flips the
// LandRecord to PENDING (approval flow itself is a later week).

import express from "express";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { prisma } from "../lib/prisma.ts";
import { requireAuth, requireRole } from "../middleware/auth.ts";
import { signTransaction, verifySignature } from "../lib/signing.ts";
import { verifyCertificate } from "../lib/ca.ts";
import type { TransactionType } from "../generated/prisma/enums.ts";
import type { TransactionModel, LandRecordModel, SignatureModel } from "../generated/prisma/models.ts";

// The actor relation on a signature is deliberately narrowed at the query
// level (see transactionWithChain) to never pull passwordHash/privateKeyRef.
interface ActorSummary {
  id: string;
  name: string;
  publicKey: string;
}

const router = express.Router();

const UPLOAD_DIR = path.resolve(process.cwd(), "uploads");
const VALID_TYPES: TransactionType[] = ["REGISTRATION", "TRANSFER", "UPDATE"];

// Exported so the transaction payload can be rebuilt identically outside
// this route (e.g. a verification script) without duplicating field order
// or shape — verifySignature() only succeeds if this exact shape is reused.
export interface TransactionPayload {
  type: string;
  landRecordId: string;
  fromOwnerId: string | null;
  toOwnerId: string;
  documentPath: string;
  documentHash: string;
  actorId: string;
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
  priorSignatures: string[];
  actorId: string;
  role: string;
  reviewedAt: string;
}

export function buildReviewPayload(fields: ReviewPayload): ReviewPayload {
  return { ...fields };
}

// Shared include shape: every review step needs the land record plus every
// signature so far, with each signature's actor. GET /pending-vo and
// GET /pending-registrar return these transactions to the client as-is, so
// the actor is deliberately `select`-ed down to name + publicKey (all that
// verification/display ever needs) rather than `include: { actor: true }`
// — the full User row carries passwordHash and the raw RSA privateKeyRef,
// neither of which should ever leave the server.
const transactionWithChain = {
  landRecord: true,
  signatures: {
    orderBy: { signedAt: "asc" as const },
    include: { actor: { select: { id: true, name: true, publicKey: true } } },
  },
} as const;

router.post("/", requireAuth, requireRole("LANDOWNER"), async (req, res) => {
  const { type, landRecordId, toOwnerId, documentPath, documentHash } = req.body ?? {};

  if (typeof type !== "string" || !VALID_TYPES.includes(type as TransactionType)) {
    res.status(400).json({ error: `type must be one of ${VALID_TYPES.join(", ")}` });
    return;
  }
  if (typeof landRecordId !== "string" || !landRecordId.trim()) {
    res.status(400).json({ error: "landRecordId is required" });
    return;
  }
  if (typeof documentPath !== "string" || !documentPath.trim()) {
    res.status(400).json({ error: "documentPath is required (from POST /api/documents/upload)" });
    return;
  }
  if (typeof documentHash !== "string" || !/^[0-9a-f]{64}$/i.test(documentHash)) {
    res.status(400).json({ error: "documentHash must be a 64-character hex SHA-256 hash" });
    return;
  }

  // Never trust a hash the server didn't independently compute: re-read the
  // file the client claims this hash belongs to and recompute it ourselves.
  // documentPath is client-supplied, so resolve it and confirm it still
  // points inside uploads/ before touching the filesystem.
  const resolvedDocumentPath = path.resolve(process.cwd(), documentPath);
  if (
    resolvedDocumentPath !== UPLOAD_DIR &&
    !resolvedDocumentPath.startsWith(UPLOAD_DIR + path.sep)
  ) {
    res.status(400).json({ error: "documentPath must reference a file under uploads/" });
    return;
  }

  let fileBuffer: Buffer;
  try {
    fileBuffer = await fs.promises.readFile(resolvedDocumentPath);
  } catch {
    res.status(400).json({ error: "No file found at documentPath" });
    return;
  }

  const actualDocumentHash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
  if (actualDocumentHash !== documentHash) {
    res.status(400).json({
      error: "Document hash mismatch — possible tampering or corrupted upload",
    });
    return;
  }

  const landRecord = await prisma.landRecord.findUnique({ where: { id: landRecordId } });
  if (!landRecord) {
    res.status(404).json({ error: "landRecord not found" });
    return;
  }

  const actorId = req.user!.userId;

  // Only the land record's current owner may act on it.
  if (landRecord.currentOwnerId !== actorId) {
    res.status(403).json({ error: "You are not the current owner of this land record" });
    return;
  }

  let fromOwnerId: string | null;
  let resolvedToOwnerId: string;

  if (type === "TRANSFER") {
    if (typeof toOwnerId !== "string" || !toOwnerId.trim()) {
      res.status(400).json({ error: "toOwnerId is required for TRANSFER transactions" });
      return;
    }
    const newOwner = await prisma.user.findUnique({ where: { id: toOwnerId } });
    if (!newOwner) {
      res.status(400).json({ error: "toOwnerId does not reference an existing user" });
      return;
    }
    fromOwnerId = actorId;
    resolvedToOwnerId = toOwnerId;
  } else {
    // REGISTRATION / UPDATE: no change of ownership, so there is no
    // "previous owner" to record — the acting landowner is toOwnerId too.
    fromOwnerId = null;
    resolvedToOwnerId = actorId;
  }

  const actor = await prisma.user.findUnique({ where: { id: actorId } });
  if (!actor) {
    res.status(401).json({ error: "Acting user no longer exists" });
    return;
  }

  // Fix the timestamp before signing/inserting so the exact same value
  // goes into both the signed payload and the stored row — if we let
  // Prisma's @default(now()) pick createdAt at insert time, we wouldn't
  // know it yet when building the payload to sign.
  const createdAt = new Date();
  const payload = buildTransactionPayload({
    type,
    landRecordId,
    fromOwnerId,
    toOwnerId: resolvedToOwnerId,
    documentPath,
    documentHash,
    actorId,
    createdAt: createdAt.toISOString(),
  });

  const { signatureValue, dataHash } = signTransaction(actor.privateKeyRef, payload);

  const result = await prisma.$transaction(async (db) => {
    const transaction = await db.transaction.create({
      data: {
        type: type as TransactionType,
        landRecordId,
        fromOwnerId,
        toOwnerId: resolvedToOwnerId,
        documentPath,
        documentHash,
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
      where: { id: landRecordId },
      data: { status: "PENDING" },
    });

    return { transaction, signature };
  });

  res.status(201).json({ ...result.transaction, signature: result.signature });
});

// ---------------------------------------------------------------------------
// Approval workflow: Village Officer stage, then Registrar stage.
// ---------------------------------------------------------------------------

export type TransactionWithChain = TransactionModel & {
  landRecord: LandRecordModel;
  signatures: (SignatureModel & { actor: ActorSummary })[];
};

function rebuildCreationPayload(transaction: TransactionWithChain, landownerActorId: string) {
  return buildTransactionPayload({
    type: transaction.type,
    landRecordId: transaction.landRecordId,
    fromOwnerId: transaction.fromOwnerId,
    toOwnerId: transaction.toOwnerId,
    documentPath: transaction.documentPath,
    documentHash: transaction.documentHash,
    actorId: landownerActorId,
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
  "id" | "type" | "landRecordId" | "fromOwnerId" | "toOwnerId" | "documentPath" | "documentHash" | "createdAt"
> & {
  signatures: (SignatureModel & { actor: ActorSummary })[];
};

// Shared by the history endpoint (routes/land-records.ts) and the
// standalone verify endpoint below — one place that knows how to rebuild
// and live-verify every signature in a transaction's chain, so both
// callers can never drift out of sync with how signing actually works.
export function verifySignatureChain(transaction: ChainableTransaction): SignatureChainResult[] {
  return transaction.signatures.map((signature, index) => {
    // The chain always starts with the landowner's creation signature;
    // every signature after it is a review chained to every prior one.
    const payload =
      signature.role === "LANDOWNER"
        ? buildTransactionPayload({
            type: transaction.type,
            landRecordId: transaction.landRecordId,
            fromOwnerId: transaction.fromOwnerId,
            toOwnerId: transaction.toOwnerId,
            documentPath: transaction.documentPath,
            documentHash: transaction.documentHash,
            actorId: signature.actorId,
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
            priorSignatures: transaction.signatures
              .slice(0, index)
              .map((s) => s.signatureValue),
            actorId: signature.actorId,
            role: signature.role,
            reviewedAt: signature.signedAt.toISOString(),
          });

    const valid = verifySignature(signature.actor.publicKey, payload, signature.signatureValue);

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
export async function checkDocumentIntegrity(transaction: {
  documentPath: string;
  documentHash: string;
}): Promise<DocumentIntegrityResult> {
  const resolvedDocumentPath = path.resolve(process.cwd(), transaction.documentPath);
  if (
    resolvedDocumentPath !== UPLOAD_DIR &&
    !resolvedDocumentPath.startsWith(UPLOAD_DIR + path.sep)
  ) {
    return { match: false, error: "documentPath is outside uploads/" };
  }

  try {
    const fileBuffer = await fs.promises.readFile(resolvedDocumentPath);
    const actualHash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
    return { match: actualHash === transaction.documentHash };
  } catch {
    return { match: false, error: "No file found at documentPath" };
  }
}

// GET /api/transactions/pending-vo
router.get(
  "/pending-vo",
  requireAuth,
  requireRole("VILLAGE_OFFICER"),
  async (_req, res) => {
    const transactions = await prisma.transaction.findMany({
      where: { status: "PENDING_VO" },
      include: transactionWithChain,
      orderBy: { createdAt: "asc" },
    });
    res.json(transactions);
  },
);

// POST /api/transactions/:id/vo-review
router.post(
  "/:id/vo-review",
  requireAuth,
  requireRole("VILLAGE_OFFICER"),
  async (req, res) => {
    const { decision, reason } = req.body ?? {};
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

    // Step 1, always: verify the existing landowner signature before doing
    // anything else. This runs regardless of what the VO submits.
    const landownerPayload = rebuildCreationPayload(transaction, landownerSignature.actorId);
    const landownerValid = verifySignature(
      landownerSignature.actor.publicKey,
      landownerPayload,
      landownerSignature.signatureValue,
    );

    if (!landownerValid) {
      const updated = await prisma.$transaction(async (db) => {
        const txn = await db.transaction.update({
          where: { id: transaction.id },
          data: { status: "REJECTED", rejectReason: "Landowner signature verification failed" },
        });
        await db.landRecord.update({
          where: { id: transaction.landRecordId },
          data: { status: "ACTIVE" },
        });
        return txn;
      });
      res.status(200).json({
        transaction: updated,
        autoRejected: true,
        reason: "Landowner signature verification failed",
      });
      return;
    }

    if (decision !== "APPROVE" && decision !== "REJECT") {
      res.status(400).json({ error: "decision must be APPROVE or REJECT" });
      return;
    }

    if (decision === "REJECT") {
      if (typeof reason !== "string" || !reason.trim()) {
        res.status(400).json({ error: "reason is required to reject" });
        return;
      }
      const updated = await prisma.$transaction(async (db) => {
        const txn = await db.transaction.update({
          where: { id: transaction.id },
          data: { status: "REJECTED", rejectReason: reason },
        });
        await db.landRecord.update({
          where: { id: transaction.landRecordId },
          data: { status: "ACTIVE" },
        });
        return txn;
      });
      res.json(updated);
      return;
    }

    // decision === "APPROVE": sign, chained to the landowner's signature.
    const voId = req.user!.userId;
    const vo = await prisma.user.findUnique({ where: { id: voId } });
    if (!vo) {
      res.status(401).json({ error: "Acting user no longer exists" });
      return;
    }

    const reviewedAt = new Date();
    const voPayload = buildReviewPayload({
      transactionId: transaction.id,
      type: transaction.type,
      landRecordId: transaction.landRecordId,
      fromOwnerId: transaction.fromOwnerId,
      toOwnerId: transaction.toOwnerId,
      documentPath: transaction.documentPath,
      documentHash: transaction.documentHash,
      priorSignatures: [landownerSignature.signatureValue],
      actorId: voId,
      role: "VILLAGE_OFFICER",
      reviewedAt: reviewedAt.toISOString(),
    });
    const { signatureValue, dataHash } = signTransaction(vo.privateKeyRef, voPayload);

    const result = await prisma.$transaction(async (db) => {
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
          dataHash,
          signedAt: reviewedAt,
        },
      });
      return { txn, signature };
    });

    res.json({ ...result.txn, signature: result.signature });
  },
);

// GET /api/transactions/pending-registrar
router.get(
  "/pending-registrar",
  requireAuth,
  requireRole("REGISTRAR"),
  async (_req, res) => {
    const transactions = await prisma.transaction.findMany({
      where: { status: "PENDING_REGISTRAR" },
      include: transactionWithChain,
      orderBy: { createdAt: "asc" },
    });
    res.json(transactions);
  },
);

// POST /api/transactions/:id/registrar-review
router.post(
  "/:id/registrar-review",
  requireAuth,
  requireRole("REGISTRAR"),
  async (req, res) => {
    const { decision, reason } = req.body ?? {};
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

    // Step 1, always: verify BOTH prior signatures before doing anything else.
    const landownerPayload = rebuildCreationPayload(transaction, landownerSignature.actorId);
    const landownerValid = verifySignature(
      landownerSignature.actor.publicKey,
      landownerPayload,
      landownerSignature.signatureValue,
    );

    const voPayload = buildReviewPayload({
      transactionId: transaction.id,
      type: transaction.type,
      landRecordId: transaction.landRecordId,
      fromOwnerId: transaction.fromOwnerId,
      toOwnerId: transaction.toOwnerId,
      documentPath: transaction.documentPath,
      documentHash: transaction.documentHash,
      priorSignatures: [landownerSignature.signatureValue],
      actorId: voSignature.actorId,
      role: "VILLAGE_OFFICER",
      reviewedAt: voSignature.signedAt.toISOString(),
    });
    const voValid = verifySignature(
      voSignature.actor.publicKey,
      voPayload,
      voSignature.signatureValue,
    );

    if (!landownerValid || !voValid) {
      const failureReason =
        !landownerValid && !voValid
          ? "Landowner and Village Officer signature verification both failed"
          : !landownerValid
            ? "Landowner signature verification failed"
            : "Village Officer signature verification failed";

      const updated = await prisma.$transaction(async (db) => {
        const txn = await db.transaction.update({
          where: { id: transaction.id },
          data: { status: "REJECTED", rejectReason: failureReason },
        });
        await db.landRecord.update({
          where: { id: transaction.landRecordId },
          data: { status: "ACTIVE" },
        });
        return txn;
      });
      res.status(200).json({ transaction: updated, autoRejected: true, reason: failureReason });
      return;
    }

    if (decision !== "APPROVE" && decision !== "REJECT") {
      res.status(400).json({ error: "decision must be APPROVE or REJECT" });
      return;
    }

    if (decision === "REJECT") {
      if (typeof reason !== "string" || !reason.trim()) {
        res.status(400).json({ error: "reason is required to reject" });
        return;
      }
      const updated = await prisma.$transaction(async (db) => {
        const txn = await db.transaction.update({
          where: { id: transaction.id },
          data: { status: "REJECTED", rejectReason: reason },
        });
        await db.landRecord.update({
          where: { id: transaction.landRecordId },
          data: { status: "ACTIVE" },
        });
        return txn;
      });
      res.json(updated);
      return;
    }

    // decision === "APPROVE": sign, chained to the VO's signature, apply
    // the ownership change (REGISTRATION/TRANSFER only), and reactivate
    // the land record.
    const registrarId = req.user!.userId;
    const registrar = await prisma.user.findUnique({ where: { id: registrarId } });
    if (!registrar) {
      res.status(401).json({ error: "Acting user no longer exists" });
      return;
    }

    const reviewedAt = new Date();
    const registrarPayload = buildReviewPayload({
      transactionId: transaction.id,
      type: transaction.type,
      landRecordId: transaction.landRecordId,
      fromOwnerId: transaction.fromOwnerId,
      toOwnerId: transaction.toOwnerId,
      documentPath: transaction.documentPath,
      documentHash: transaction.documentHash,
      priorSignatures: [landownerSignature.signatureValue, voSignature.signatureValue],
      actorId: registrarId,
      role: "REGISTRAR",
      reviewedAt: reviewedAt.toISOString(),
    });
    const { signatureValue, dataHash } = signTransaction(registrar.privateKeyRef, registrarPayload);

    const result = await prisma.$transaction(async (db) => {
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
          dataHash,
          signedAt: reviewedAt,
        },
      });

      const landRecordUpdate: { status: "ACTIVE"; currentOwnerId?: string } = {
        status: "ACTIVE",
      };
      if (transaction.type === "REGISTRATION" || transaction.type === "TRANSFER") {
        landRecordUpdate.currentOwnerId = transaction.toOwnerId;
      }
      const landRecord = await db.landRecord.update({
        where: { id: transaction.landRecordId },
        data: landRecordUpdate,
      });

      return { txn, signature, landRecord };
    });

    res.json({ ...result.txn, signature: result.signature, landRecord: result.landRecord });
  },
);

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

  const signerIdentity = await Promise.all(
    chain.map(async (link) => {
      const certificate = await prisma.certificate.findUnique({
        where: { subjectUserId: link.actorId },
      });
      const certificateValid = certificate
        ? (await verifyCertificate(certificate.id)).valid
        : false;
      return {
        actorId: link.actorId,
        actorName: link.actorName,
        role: link.role,
        certificateValid,
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
