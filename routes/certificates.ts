// routes/certificates.ts
//
// GET  /api/certificates/crl            — the Certificate Revocation List:
//                                          every revoked certificate (plain,
//                                          unsigned — feeds the Admin UI's
//                                          CRL table only).
// GET  /api/certificates/ca             — the root + issuing CA certificates
//                                          (PEM, public), so the browser can
//                                          verify the full chain itself.
// GET  /api/certificates/crl/signed     — a real, CA-signed X.509 CRL (PEM)
//                                          for the browser's own verification.
// GET  /api/certificates/search         — name search, VO/Registrar/Admin only.
// GET  /api/certificates/serial/:serial — exact lookup by the certificate's
//                                          real X.509 serial number, public
//                                          fields only, immutably cacheable.
// POST /api/certificates/:id/revoke     — ADMIN-only. Revokes a certificate
//                                          by its own id (not the subject's
//                                          user id, and not its serial).
// GET  /api/certificates/:userId        — legacy lookup by SUBJECT USER id
//                                          (not a certificate id or serial).
//                                          Left working — AdminDashboard's
//                                          revoke flow depends on this exact
//                                          shape (getCertificateByUserId).
//
// Route order matters: every specific path below (/crl, /crl/signed, /ca,
// /search, /serial/:serial) must be declared before the generic /:userId
// catch-all, or Express would swallow e.g. "ca" as a userId value.

import express from "express";
import { prisma } from "../lib/prisma.ts";
import { requireAuth, requireRole } from "../middleware/auth.ts";
import { directoryLookupRateLimiter } from "../middleware/rateLimit.ts";
import { appendAuditEntry } from "../lib/audit.ts";
import {
  verifyCertificate,
  revokeCertificate,
  getCRL,
  getCAPublicCertificates,
  getSignedCRL,
  publicKeyPemFromCertificatePem,
} from "../lib/ca.ts";
import type { Role } from "../generated/prisma/enums.ts";

const router = express.Router();

const SEARCHABLE_ROLES: Role[] = ["VILLAGE_OFFICER", "REGISTRAR", "ADMIN"];
const SEARCH_MIN_QUERY_LENGTH = 3;
const SEARCH_PAGE_SIZE = 10;

// GET /api/certificates/crl — declared before /:userId so "crl" is never
// swallowed as a userId path param.
router.get("/crl", requireAuth, async (_req, res) => {
  const crl = await getCRL();
  res.json(crl);
});

// GET /api/certificates/crl/signed — a real, CA-signed X.509 CRL for the
// browser's own verification (frontend/src/lib/certificateVerify.ts).
// Cache-Control's max-age is computed from the CRL's own stated freshness
// window, not a flat constant — a cached copy is never served past the
// moment the CRL itself says it goes stale.
router.get("/crl/signed", requireAuth, async (_req, res) => {
  const signedCrl = await getSignedCRL();
  const secondsUntilNextUpdate = Math.max(
    0,
    Math.floor((new Date(signedCrl.nextUpdate).getTime() - Date.now()) / 1000),
  );
  res.set("Cache-Control", `private, max-age=${secondsUntilNextUpdate}`);
  res.json(signedCrl);
});

// GET /api/certificates/ca — the root + issuing CA certificates (public).
// Authenticated for consistency with every other route in this app, not
// because these certificates are themselves sensitive (they aren't —
// they're meant to be public).
//
// IMPORTANT caveat, not solved here: fetching this from the same server
// that issued the certificates you're about to verify with it does not by
// itself establish trust — a server that could forge certificates could
// just as easily serve forged "CA certificates" to match. In a real
// deployment the root certificate (or its fingerprint) would be pinned
// into the client application / OS trust store out-of-band, not fetched
// live from the thing it's meant to be checking.
router.get("/ca", requireAuth, async (_req, res) => {
  res.json(await getCAPublicCertificates());
});

// GET /api/certificates/search?q=&cursor= — name search. Restricted to
// VILLAGE_OFFICER/REGISTRAR/ADMIN (a Landowner has no legitimate reason to
// browse other identities by name — they only ever need to check one
// specific certificate they already have the serial for). Keyset
// (cursor), not offset, pagination: ordered by (name, id), keyed by the
// last row's own (name, id) tuple, backed by the users_name_idx index.
router.get(
  "/search",
  requireAuth,
  requireRole(...SEARCHABLE_ROLES),
  directoryLookupRateLimiter,
  async (req, res) => {
    const q = typeof req.query.q === "string" ? req.query.q.trim() : "";
    if (q.length < SEARCH_MIN_QUERY_LENGTH) {
      res.json({ results: [], nextCursor: null });
      return;
    }

    // Keyset tie-break: (name > cursorName) OR (name = cursorName AND id >
    // cursorId) — the standard pattern for ORDER BY name, id with a cursor
    // on the last row seen. Plain (case-sensitive) comparison here, same
    // collation the ORDER BY itself uses; only the match filter below
    // (startsWith) is case-insensitive.
    const cursorRaw = typeof req.query.cursor === "string" ? req.query.cursor : null;
    const [cursorName, cursorId] = cursorRaw ? cursorRaw.split("\u0000") : [undefined, undefined];
    const cursorCondition =
      cursorName !== undefined && cursorId !== undefined
        ? { OR: [{ name: { gt: cursorName } }, { name: cursorName, id: { gt: cursorId } }] }
        : {};

    const rows = await prisma.user.findMany({
      where: {
        name: { startsWith: q, mode: "insensitive" },
        // This is a CERTIFICATE search, not a general directory — a user
        // with no certificate has nothing to verify, so they're excluded
        // rather than surfaced as a dead end the caller would have to
        // special-case.
        certificate: { isNot: null },
        ...cursorCondition,
      },
      select: { id: true, name: true, role: true, certificate: { select: { serialNumber: true } } },
      orderBy: [{ name: "asc" }, { id: "asc" }],
      take: SEARCH_PAGE_SIZE + 1,
    });

    const hasMore = rows.length > SEARCH_PAGE_SIZE;
    const page = rows.slice(0, SEARCH_PAGE_SIZE);
    const last = page[page.length - 1];
    const nextCursor = hasMore && last ? `${last.name}\u0000${last.id}` : null;

    await appendAuditEntry({
      action: "CERTIFICATE_SEARCH",
      actorUserId: req.user!.userId,
      entityType: "USER",
      entityId: null,
      details: { query: q, resultCount: page.length },
    });

    res.json({
      // The real X.509 serial, not the user id or the certificate's own
      // cuid — the next step for whoever picks a result is GET
      // /serial/:serial, which takes a serial number.
      results: page.map((row) => ({ serial: row.certificate!.serialNumber, name: row.name, role: row.role })),
      nextCursor,
    });
  },
);

// GET /api/certificates/serial/:serial — exact lookup by the certificate's
// real X.509 serial number. Any authenticated user.
//
// Returns ONLY the raw certificate PEM (plus the issuing CA's own PEM, so
// the browser can verify the chain without a second request) — nothing
// the server has computed (no valid/reason/revoked verdict): the browser
// verifies the full chain, validity, CRL freshness, and revocation itself
// (frontend/src/lib/certificateVerify.ts). Because the certificate PEM
// itself can never change after issuance (revocation status lives only in
// the separately-fetched, short-lived signed CRL), it's safe to cache as
// `immutable`. `private`, not `public`, because this is still an
// authenticated route — a shared/corporate cache must not store it on the
// authenticated user's behalf.
router.get("/serial/:serial", requireAuth, directoryLookupRateLimiter, async (req, res) => {
  const cert = await prisma.certificate.findUnique({
    where: { serialNumber: req.params.serial },
    include: { subject: { select: { name: true } } },
  });

  if (!cert) {
    res.status(404).json({ error: "No certificate found for this serial" });
    return;
  }

  const { issuingCertPem } = await getCAPublicCertificates();

  await appendAuditEntry({
    action: "CERTIFICATE_LOOKUP",
    actorUserId: req.user!.userId,
    entityType: "CERTIFICATE",
    entityId: cert.id,
    details: { serialNumber: cert.serialNumber },
  });

  res.set("Cache-Control", "private, max-age=31536000, immutable");
  res.json({
    serialNumber: cert.serialNumber,
    certificatePem: cert.certificatePem,
    issuingCertificatePem: issuingCertPem,
  });
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
  // row carries passwordHash and wrapped key material.
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
    publicKey: publicKeyPemFromCertificatePem(certificate.certificatePem),
    serialNumber: certificate.serialNumber,
    issuer: details.issuer,
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
