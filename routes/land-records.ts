// routes/land-records.ts
//
// POST /api/land-records — Registrar-only. Seeds a new land parcel into
// the system with its initial owner. Status defaults to ACTIVE (schema
// default); ownership then moves through routes/transactions.ts.

import express from "express";
import { prisma } from "../lib/prisma.ts";
import { requireAuth, requireCertifiedRole } from "../middleware/auth.ts";
import { directoryLookupRateLimiter } from "../middleware/rateLimit.ts";
import { verifySignatureChain, checkDocumentIntegrity } from "./transactions.ts";
import { verifyCertificate } from "../lib/ca.ts";
import { findSignatureAcceptedAt } from "../lib/audit.ts";
import type { AreaUnit } from "../generated/prisma/enums.ts";

const VALID_AREA_UNITS: AreaUnit[] = ["HECTARE", "ACRE"];
const SEARCH_MIN_QUERY_LENGTH = 3;
const SEARCH_RESULT_CAP = 10;

const router = express.Router();

// GET /api/land-records/search?q= — exact-prefix survey-number search,
// any authenticated role, NOT scoped to the caller's own records. Backs
// the "Claim as legal heir" flow: an heir needs to find a record they
// don't own (the deceased's), which GET / above can never return for a
// Landowner. Declared before /:id/history so "search" is never swallowed
// as an :id value — though that route is two segments (/:id/history) so
// this one-segment path wouldn't collide anyway; kept here for clarity.
// Same anti-enumeration shape as the other directory-style searches in
// this app (3-char minimum, capped results, shared rate limit) — a survey
// number is far less sensitive than a name or email, but still not worth
// turning into an unbounded scan.
router.get("/search", requireAuth, directoryLookupRateLimiter, async (req, res) => {
  const q = typeof req.query.q === "string" ? req.query.q.trim() : "";
  if (q.length < SEARCH_MIN_QUERY_LENGTH) {
    res.json([]);
    return;
  }

  const records = await prisma.landRecord.findMany({
    where: { surveyNumber: { startsWith: q, mode: "insensitive" } },
    include: { currentOwner: { select: { name: true } } },
    orderBy: { surveyNumber: "asc" },
    take: SEARCH_RESULT_CAP,
  });

  res.json(
    records.map((r) => ({
      id: r.id,
      surveyNumber: r.surveyNumber,
      location: r.location,
      currentOwnerName: r.currentOwner.name,
      status: r.status,
    })),
  );
});

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

router.post("/", requireAuth, requireCertifiedRole("REGISTRAR"), async (req, res) => {
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
  const landRecord = await prisma.landRecord.findUnique({
    where: { id: req.params.id },
    include: { currentOwner: { select: { name: true } } },
  });
  // A Landowner who isn't the current owner gets exactly the same 404 as a
  // land record that doesn't exist at all — a 403 here would confirm the
  // ID is real, which is itself information this endpoint shouldn't leak.
  // Village Officers and Registrars are unrestricted (same as GET / above):
  // they need visibility across every record to review transactions
  // against any of them.
  if (!landRecord || (req.user!.role === "LANDOWNER" && landRecord.currentOwnerId !== req.user!.userId)) {
    res.status(404).json({ error: "landRecord not found" });
    return;
  }

  const transactions = await prisma.transaction.findMany({
    where: { landRecordId: req.params.id },
    orderBy: { createdAt: "asc" },
    include: {
      // Only ever .name — never the full User row (no passwordHash/wrapped
      // key material), same discipline as the signature actor select below.
      fromOwner: { select: { name: true } },
      toOwner: { select: { name: true } },
      signatures: {
        orderBy: { signedAt: "asc" },
        // select, not include: true — the actor's passwordHash/wrapped key material
        // must never be fetched here even though this response strips the
        // raw signatures array before sending (see below). certificate's
        // certificatePem is what verifySignatureChain() now derives the
        // actor's public key from (see routes/transactions.ts's
        // actorPublicKeyPem()) — without it, every signature here would
        // silently verify as invalid regardless of its actual validity.
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
    },
  });

  const transactionsWithLiveVerification = await Promise.all(
    transactions.map(async (transaction) => {
      const chain = verifySignatureChain(transaction);
      // certificateValid is "valid AT SIGNING TIME", not "valid right
      // now" — see routes/transactions.ts's GET /:id/verify for the full
      // rationale (a certificate revoked later, e.g. a deceased SUCCESSION
      // owner, must not retroactively invalidate a genuine prior signature).
      const signatureResults = await Promise.all(
        chain.map(async (link) => {
          const certificateRow = await prisma.certificate.findUnique({ where: { subjectUserId: link.actorId } });
          if (!certificateRow) {
            return {
              actorName: link.actorName,
              role: link.role,
              signedAt: link.signedAt,
              valid: link.valid,
              certificateValid: false,
              certificateReason: "No certificate found for this user.",
              currentlyRevoked: false,
              currentlyRevokedReason: null,
              signingTimeTrusted: false,
            };
          }
          const acceptedAt = await findSignatureAcceptedAt(transaction.id, link.actorId, link.role);
          const trusted = acceptedAt !== null;
          const asOfResult = await verifyCertificate(certificateRow.id, acceptedAt ?? new Date());
          const nowResult = await verifyCertificate(certificateRow.id);
          return {
            actorName: link.actorName,
            role: link.role,
            signedAt: link.signedAt,
            valid: link.valid, // live check, not the cached `valid` column
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
      const documentIntegrity = await checkDocumentIntegrity(transaction);

      const { signatures: _signatures, fromOwner, toOwner, ...transactionFields } = transaction;
      return {
        ...transactionFields,
        fromOwnerName: fromOwner?.name ?? null,
        toOwnerName: toOwner.name,
        signatures: signatureResults,
        documentIntegrity,
      };
    }),
  );

  const { currentOwner, ...landRecordFields } = landRecord;
  res.json({
    landRecord: { ...landRecordFields, currentOwnerName: currentOwner.name },
    transactions: transactionsWithLiveVerification,
  });
});

export default router;
