// routes/audit.ts
//
// GET /api/audit                — ADMIN-only. Paginated, newest first.
// GET /api/audit/head           — ADMIN-only. Latest seq + hash, for a
//                                  quick "has anything changed since I last
//                                  checked" comparison without pulling the
//                                  whole log.
// GET /api/audit/verify         — ADMIN-only. Recomputes and checks the
//                                  entire chain. The check itself is logged
//                                  (after being computed, so the log entry
//                                  it creates is never part of the range it
//                                  just verified). Also carries the latest
//                                  RFC 3161 anchor's own check, under a
//                                  clearly separate `anchor` field — never
//                                  folded into `valid`, since an anchor
//                                  problem and a hash-chain problem are
//                                  different findings a reader should be
//                                  able to tell apart.
// GET /api/audit/anchors        — ADMIN-only. Latest 20 RFC 3161 anchors,
//                                  no raw tokens (lib/timestamp.ts).
// GET /api/audit/anchors/verify — ADMIN-only. Runs every check for the
//                                  latest N anchors (default 20).
// POST /api/audit/anchor        — ADMIN-only, rate limited. Anchors the
//                                  current chain head now, subject to
//                                  TSA_MIN_INTERVAL_SECONDS regardless of
//                                  how recently this same endpoint was
//                                  last called (lib/timestamp.ts enforces
//                                  this once, for every caller).

import express from "express";
import { requireAuth, requireRole } from "../middleware/auth.ts";
import { anchorRateLimiter } from "../middleware/rateLimit.ts";
import { verifyAuditChain, getAuditHead, listAuditEntries, appendAuditEntry } from "../lib/audit.ts";
import { anchorAuditChain, listAnchors, verifyAnchors } from "../lib/timestamp.ts";

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

  // The latest anchor's own check, as a clearly separate field — `null`
  // when nothing has ever been anchored yet, never folded into `valid`
  // above (a hash-chain break and an anchor problem are different findings).
  const [latestAnchor] = await verifyAnchors(1);

  res.json({ ...result, anchor: latestAnchor ?? null });
});

router.get("/anchors", requireAuth, requireRole("ADMIN"), async (_req, res) => {
  const anchors = await listAnchors(20);
  res.json({ anchors });
});

router.get("/anchors/verify", requireAuth, requireRole("ADMIN"), async (req, res) => {
  const limitRaw = Number(req.query.limit);
  const limit = Number.isInteger(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 100) : 20;
  const results = await verifyAnchors(limit);
  res.json({ results });
});

router.post("/anchor", requireAuth, requireRole("ADMIN"), anchorRateLimiter, async (_req, res) => {
  const result = await anchorAuditChain();
  if (result.outcome === "failed") {
    // A TSA problem is an operational condition, not a client error — 502
    // (bad gateway: this server's own upstream, the TSA, misbehaved), not
    // 400/500, so the admin UI can tell "the TSA said no" apart from "this
    // server has a bug".
    res.status(502).json({ outcome: result.outcome, reason: result.reason });
    return;
  }
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
