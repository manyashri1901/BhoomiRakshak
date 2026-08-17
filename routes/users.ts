// routes/users.ts
//
// GET /api/users — minimal directory lookup, needed by two frontend
// features: the Registrar's "select owner" picker when creating a land
// record, and the certificate lookup page's search-by-name/role entry
// point. Optional ?role= and ?q= (name substring) filters.

import express from "express";
import { prisma } from "../lib/prisma.ts";
import { requireAuth } from "../middleware/auth.ts";
import type { Role } from "../generated/prisma/enums.ts";

const router = express.Router();

const VALID_ROLES: Role[] = ["LANDOWNER", "VILLAGE_OFFICER", "REGISTRAR"];

router.get("/", requireAuth, async (req, res) => {
  const { role, q } = req.query;

  const where: { role?: Role; name?: { contains: string; mode: "insensitive" } } = {};
  if (typeof role === "string" && VALID_ROLES.includes(role as Role)) {
    where.role = role as Role;
  }
  if (typeof q === "string" && q.trim()) {
    where.name = { contains: q.trim(), mode: "insensitive" };
  }

  const users = await prisma.user.findMany({
    where,
    select: { id: true, name: true, role: true },
    orderBy: { name: "asc" },
    take: 20,
  });

  res.json(users);
});

export default router;
