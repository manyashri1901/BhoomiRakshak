// routes/users.ts
//
// GET /api/users — minimal directory lookup, needed by two frontend
// features: the Registrar's "select owner" picker when creating a land
// record, and the Landowner's "select new owner" picker for a TRANSFER.
// Optional ?role= and ?q= (name prefix) filters.
//
// This is still an identity-enumeration surface even with role scoping,
// so it's deliberately bounded the same way the certificate search
// endpoint is: a 3-character minimum on `q` (empty result below that,
// not an error — there's a legitimate picker UI on the other end of this,
// not just an attack target), a hard cap of 10 rows, and its own rate
// limit shared with the other directory-style lookups. Only id/name/role
// are ever selected — never email or any credential/key material.

import express from "express";
import { prisma } from "../lib/prisma.ts";
import { requireAuth } from "../middleware/auth.ts";
import { directoryLookupRateLimiter } from "../middleware/rateLimit.ts";
import type { Role } from "../generated/prisma/enums.ts";

const router = express.Router();

const VALID_ROLES: Role[] = ["LANDOWNER", "VILLAGE_OFFICER", "REGISTRAR"];
const SEARCH_MIN_QUERY_LENGTH = 3;
const RESULT_CAP = 10;

router.get("/", requireAuth, directoryLookupRateLimiter, async (req, res) => {
  const { role, q } = req.query;

  const query = typeof q === "string" ? q.trim() : "";
  if (query.length < SEARCH_MIN_QUERY_LENGTH) {
    res.json([]);
    return;
  }

  const where: { role?: Role; name: { startsWith: string; mode: "insensitive" } } = {
    name: { startsWith: query, mode: "insensitive" },
  };
  if (typeof role === "string" && VALID_ROLES.includes(role as Role)) {
    where.role = role as Role;
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
