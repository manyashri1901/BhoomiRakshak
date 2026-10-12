// routes/audit.ts
//
// GET /api/audit         — ADMIN-only. Paginated, newest first.
// GET /api/audit/head    — ADMIN-only. Latest seq + hash, for a quick
//                           "has anything changed since I last checked"
//                           comparison without pulling the whole log.
// GET /api/audit/verify  — ADMIN-only. Recomputes and checks the entire
//                           chain. The check itself is logged (after being
//                           computed, so the log entry it creates is never
//                           part of the range it just verified).

import express from "express";
import { requireAuth, requireRole } from "../middleware/auth.ts";
import { verifyAuditChain, getAuditHead, listAuditEntries, appendAuditEntry } from "../lib/audit.ts";

const router = express.Router();

router.get("/head", requireAuth, requireRole("ADMIN"), async (_req, res) => {
  const head = await getAuditHead();
  res.json(head ?? { seq: 0, hash: null });
});

router.get("/verify", requireAuth, requireRole("ADMIN"), async (req, res) => {
  const result = await verifyAuditChain();

  await appendAuditEntry({
    action: "AUDIT_INTEGRITY_CHECK",
    actorUserId: req.user!.userId,
    entityType: "AUDIT_LOG",
    details: { valid: result.valid, checked: result.checked, firstBrokenSeq: result.firstBrokenSeq },
  });

  res.json(result);
});

router.get("/", requireAuth, requireRole("ADMIN"), async (req, res) => {
  const pageRaw = Number(req.query.page);
  const pageSizeRaw = Number(req.query.pageSize);
  const page = Number.isInteger(pageRaw) && pageRaw > 0 ? pageRaw : 1;
  const pageSize =
    Number.isInteger(pageSizeRaw) && pageSizeRaw > 0 ? Math.min(pageSizeRaw, 200) : 50;

  const result = await listAuditEntries({ page, pageSize });
  res.json(result);
});

export default router;
