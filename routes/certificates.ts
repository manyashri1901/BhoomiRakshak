// routes/certificates.ts
//
// GET /api/certificates/:userId — "any stakeholder can verify another
// user's certificate against the CA" (case study). Looks a certificate up
// by its subject's user ID and re-verifies it live via lib/ca.ts, rather
// than trusting the cached signature.

import express from "express";
import { prisma } from "../lib/prisma.ts";
import { requireAuth } from "../middleware/auth.ts";
import { verifyCertificate } from "../lib/ca.ts";

const router = express.Router();

router.get("/:userId", requireAuth, async (req, res) => {
  // select, not include: true — only .name is used below; the full User
  // row carries passwordHash and the raw RSA privateKeyRef.
  const certificate = await prisma.certificate.findUnique({
    where: { subjectUserId: req.params.userId },
    include: { subject: { select: { name: true } } },
  });

  if (!certificate) {
    res.status(404).json({ error: "No certificate found for this user" });
    return;
  }

  const { valid } = await verifyCertificate(certificate.id);

  res.json({
    id: certificate.id,
    subjectUserId: certificate.subjectUserId,
    subjectName: certificate.subject.name,
    role: certificate.role,
    publicKey: certificate.publicKey,
    issuer: certificate.issuer,
    issuedAt: certificate.issuedAt,
    fingerprint: certificate.fingerprint,
    valid,
  });
});

export default router;
