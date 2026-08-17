// routes/dev.ts
//
// DEMO-ONLY. This route exists purely to make the tamper-evidence property
// of the signing/verification system demonstrable (case study §6.5) — it
// would never exist in a production deployment. It deliberately bypasses
// the app's entire signing flow (lib/signing.ts is never called) and
// writes straight to the database, simulating what a database-level
// attacker could do: a compromised DB credential, a raw SQL statement, a
// backup restored from a tampered snapshot. None of BhoomiRakshak's normal
// request paths can produce this write — the point is that even though
// the tamper happened completely outside the application, both
// GET /api/land-records/:id/history and GET /api/transactions/:id/verify
// still catch it, because they re-verify signatures against the payload
// that's actually stored now, not a cached "this was fine when it was
// created" flag.

import express from "express";
import * as crypto from "node:crypto";
import { prisma } from "../lib/prisma.ts";
import { requireAuth, requireRole } from "../middleware/auth.ts";

const router = express.Router();

// POST /api/dev/tamper/:transactionId
// Overwrites Transaction.documentHash with an unrelated, well-formed hash —
// exactly the kind of change a real attacker would make to redirect a
// transaction to a different document without anyone noticing, if the
// system only trusted what was in the database.
router.post("/tamper/:transactionId", requireAuth, requireRole("REGISTRAR"), async (req, res) => {
  const transaction = await prisma.transaction.findUnique({
    where: { id: req.params.transactionId },
  });
  if (!transaction) {
    res.status(404).json({ error: "Transaction not found" });
    return;
  }

  const tamperedHash = crypto.randomBytes(32).toString("hex");

  const updated = await prisma.transaction.update({
    where: { id: transaction.id },
    data: { documentHash: tamperedHash },
  });

  res.json(updated);
});

export default router;
