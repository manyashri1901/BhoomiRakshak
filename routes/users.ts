// routes/users.ts
//
// GET /api/users — minimal directory lookup, needed by two frontend
// features: the Registrar's "select owner" picker when creating a land
// record, and the Landowner's "select new owner" picker for a TRANSFER.
// Optional ?role= (filter), ?q= (name prefix OR exact email), and
// ?excludeUserId= (drop one id from the results, e.g. so a transfer's
// "new owner" picker can never offer the seller themselves) filters.
//
// This is still an identity-enumeration surface even with role scoping,
// so it's deliberately bounded the same way the certificate search
// endpoint is: a 3-character minimum on `q` (empty result below that,
// not an error — there's a legitimate picker UI on the other end of this,
// not just an attack target), a hard cap of 10 rows, and its own rate
// limit shared with the other directory-style lookups. Only id/name/role
// are ever selected — never email or any credential/key material. Email
// matching is deliberately EXACT, not a prefix/contains scan like name —
// finding someone by email requires already knowing their email in full,
// so this can't be used to enumerate addresses the way a name search can.

import express from "express";
import { prisma } from "../lib/prisma.ts";
import { requireAuth } from "../middleware/auth.ts";
import { directoryLookupRateLimiter } from "../middleware/rateLimit.ts";
import type { Role } from "../generated/prisma/enums.ts";

const router = express.Router();

const VALID_ROLES: Role[] = ["LANDOWNER", "VILLAGE_OFFICER", "REGISTRAR"];
const SEARCH_MIN_QUERY_LENGTH = 3;
const RESULT_CAP = 10;

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

router.get("/", requireAuth, directoryLookupRateLimiter, async (req, res) => {
  const { role, q, excludeUserId } = req.query;

  const query = typeof q === "string" ? q.trim() : "";
  if (query.length < SEARCH_MIN_QUERY_LENGTH) {
    res.json([]);
    return;
  }

  const where: {
    role?: Role;
    id?: { not: string };
    name?: { startsWith: string; mode: "insensitive" };
    email?: string;
  } = EMAIL_PATTERN.test(query)
    ? { email: query.toLowerCase() }
    : { name: { startsWith: query, mode: "insensitive" } };
  if (typeof role === "string" && VALID_ROLES.includes(role as Role)) {
    where.role = role as Role;
  }
  if (typeof excludeUserId === "string" && excludeUserId.trim()) {
    where.id = { not: excludeUserId };
  }

  const users = await prisma.user.findMany({
    where,
    select: { id: true, name: true, role: true },
    orderBy: { name: "asc" },
    take: RESULT_CAP,
  });

  res.json(users);
});

export default router;
