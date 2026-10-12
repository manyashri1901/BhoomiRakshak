// routes/certificates.ts
//
// GET  /api/certificates/:userId        — "any stakeholder can verify another
//                                          user's certificate against the CA"
//                                          (case study). Re-verifies live via
//                                          lib/ca.ts, rather than trusting the
//                                          cached signature.
// GET  /api/certificates/crl            — the Certificate Revocation List:
//                                          every revoked certificate.
// POST /api/certificates/:id/revoke     — ADMIN-only. Revokes a certificate
//                                          by its own id (not the subject's
//                                          user id).

import express from "express";
import { prisma } from "../lib/prisma.ts";
import { requireAuth, requireRole } from "../middleware/auth.ts";
import { verifyCertificate, revokeCertificate, getCRL } from "../lib/ca.ts";

const router = express.Router();

// GET /api/certificates/crl — declared before /:userId so "crl" is never
// swallowed as a userId path param.
router.get("/crl", requireAuth, async (_req, res) => {
  const crl = await getCRL();
  res.json(crl);
});

router.post("/:id/revoke", requireAuth, requireRole("ADMIN"), async (req, res) => {
  const { reason } = req.body ?? {};
  if (typeof reason !== "string" || !reason.trim()) {
    res.status(400).json({ error: "reason is required to revoke a certificate" });
    return;
  }

  try {
    const revoked = await revokeCertificate({
      certificateId: req.params.id,
      revokedByUserId: req.user!.userId,
      reason: reason.trim(),
    });
    res.json(revoked);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Revocation failed";
    if (message.startsWith("Certificate not found")) {
      res.status(404).json({ error: message });
      return;
    }
    if (message === "Certificate is already revoked") {
      res.status(409).json({ error: message });
      return;
    }
    throw err;
  }
});

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

  const { valid, details } = await verifyCertificate(certificate.id);

  res.json({
    id: certificate.id,
    subjectUserId: certificate.subjectUserId,
    subjectName: certificate.subject.name,
    role: certificate.role,
    publicKey: certificate.publicKey,
    issuer: certificate.issuer,
    issuedAt: certificate.issuedAt,
    expiresAt: certificate.expiresAt,
    fingerprint: certificate.fingerprint,
    revoked: certificate.revoked,
    revokedAt: certificate.revokedAt,
    revokedReason: certificate.revokedReason,
    valid,
    reason: details.reason,
  });
});

export default router;
