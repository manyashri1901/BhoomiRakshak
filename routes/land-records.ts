// routes/land-records.ts
//
// POST /api/land-records — Registrar-only. Seeds a new land parcel into
// the system with its initial owner. Status defaults to ACTIVE (schema
// default); ownership then moves through routes/transactions.ts.

import express from "express";
import { prisma } from "../lib/prisma.ts";
import { requireAuth, requireRole } from "../middleware/auth.ts";
import { verifySignatureChain, checkDocumentIntegrity } from "./transactions.ts";
import type { AreaUnit } from "../generated/prisma/enums.ts";

const VALID_AREA_UNITS: AreaUnit[] = ["HECTARE", "ACRE"];

const router = express.Router();

// GET /api/land-records — Landowners see only their own records; Village
// Officers and Registrars see everything (they need visibility across
// records to review transactions against any of them).
router.get("/", requireAuth, async (req, res) => {
  const where = req.user!.role === "LANDOWNER" ? { currentOwnerId: req.user!.userId } : {};

  const landRecords = await prisma.landRecord.findMany({
    where,
    include: { currentOwner: { select: { name: true } } },
    orderBy: { createdAt: "desc" },
  });

  res.json(
    landRecords.map((lr) => ({
      id: lr.id,
      surveyNumber: lr.surveyNumber,
      location: lr.location,
      area: lr.area,
      areaUnit: lr.areaUnit,
      status: lr.status,
      createdAt: lr.createdAt,
      currentOwnerId: lr.currentOwnerId,
      currentOwnerName: lr.currentOwner.name,
    })),
  );
});

router.post("/", requireAuth, requireRole("REGISTRAR"), async (req, res) => {
  const { surveyNumber, location, area, areaUnit, currentOwnerId } = req.body ?? {};

  if (typeof surveyNumber !== "string" || !surveyNumber.trim()) {
    res.status(400).json({ error: "surveyNumber is required" });
    return;
  }
  if (typeof location !== "string" || !location.trim()) {
    res.status(400).json({ error: "location is required" });
    return;
  }
  if (typeof area !== "number" || !Number.isFinite(area) || area <= 0) {
    res.status(400).json({ error: "area must be a positive number" });
    return;
  }
  // areaUnit is optional and defaults to HECTARE — but if the caller does
  // supply one, it must be a real AreaUnit value, not silently coerced.
  let resolvedAreaUnit: AreaUnit = "HECTARE";
  if (areaUnit !== undefined) {
    if (typeof areaUnit !== "string" || !VALID_AREA_UNITS.includes(areaUnit as AreaUnit)) {
      res.status(400).json({ error: `areaUnit must be one of ${VALID_AREA_UNITS.join(", ")}` });
      return;
    }
    resolvedAreaUnit = areaUnit as AreaUnit;
  }
  if (typeof currentOwnerId !== "string" || !currentOwnerId.trim()) {
    res.status(400).json({ error: "currentOwnerId is required" });
    return;
  }

  const owner = await prisma.user.findUnique({ where: { id: currentOwnerId } });
  if (!owner) {
    res.status(400).json({ error: "currentOwnerId does not reference an existing user" });
    return;
  }

  try {
    const landRecord = await prisma.landRecord.create({
      data: {
        surveyNumber: surveyNumber.trim(),
        location: location.trim(),
        area,
        areaUnit: resolvedAreaUnit,
        currentOwnerId,
      },
    });
    res.status(201).json(landRecord);
  } catch (err: unknown) {
    if (typeof err === "object" && err !== null && "code" in err && err.code === "P2002") {
      res.status(409).json({ error: "surveyNumber already exists" });
      return;
    }
    throw err;
  }
});

// GET /api/land-records/:id/history — the tamper-evident audit trail: the
// land record plus every transaction against it in chronological order,
// and for each transaction, every signature in its chain re-verified LIVE
// (not the cached `valid` column) against the actor's stored public key,
// plus a live documentIntegrity re-hash — so a DB-level tamper of either
// the stored documentHash or a signature is visible here immediately.
router.get("/:id/history", requireAuth, async (req, res) => {
  const landRecord = await prisma.landRecord.findUnique({ where: { id: req.params.id } });
  if (!landRecord) {
    res.status(404).json({ error: "landRecord not found" });
    return;
  }

  const transactions = await prisma.transaction.findMany({
    where: { landRecordId: req.params.id },
    orderBy: { createdAt: "asc" },
    include: {
      signatures: {
        orderBy: { signedAt: "asc" },
        // select, not include: true — the actor's passwordHash/privateKeyRef
        // must never be fetched here even though this response strips the
        // raw signatures array before sending (see below).
        include: { actor: { select: { id: true, name: true, publicKey: true } } },
      },
    },
  });

  const transactionsWithLiveVerification = await Promise.all(
    transactions.map(async (transaction) => {
      const signatureResults = verifySignatureChain(transaction).map((link) => ({
        actorName: link.actorName,
        role: link.role,
        signedAt: link.signedAt,
        valid: link.valid, // live check, not the cached `valid` column
      }));
      const documentIntegrity = await checkDocumentIntegrity(transaction);

      const { signatures: _signatures, ...transactionFields } = transaction;
      return { ...transactionFields, signatures: signatureResults, documentIntegrity };
    }),
  );

  res.json({ landRecord, transactions: transactionsWithLiveVerification });
});

export default router;
