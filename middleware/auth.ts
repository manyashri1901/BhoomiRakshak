// middleware/auth.ts
//
// Session auth for the HTTP API. This is intentionally separate from the
// PKI layer in lib/ca.ts: JWTs here only prove "this request came from a
// logged-in session for user X with role Y" to the Express app. They are
// never used to sign land records, transactions, or certificates — that
// trust chain runs entirely through each user's RSA keypair and the CA.

import jwt from "jsonwebtoken";
import type { NextFunction, Request, Response } from "express";
// Must precede the "@peculiar/x509" import below: its tsyringe dependency
// requires this polyfill at load time, not just before first use.
import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { prisma } from "../lib/prisma.ts";
import { verifyCertificateForUser } from "../lib/ca.ts";
import { appendAuditEntry } from "../lib/audit.ts";

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is not set (check .env)");
}

export interface AuthUser {
  userId: string;
  role: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

/**
 * Verifies the JWT in the `Authorization: Bearer <token>` header and
 * attaches { userId, role } to req.user. 401s on anything else: missing
 * header, malformed header, expired token, bad signature.
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    res.status(401).json({ error: "Missing or malformed Authorization header" });
    return;
  }

  const token = header.slice("Bearer ".length);
  try {
    const payload = jwt.verify(token, JWT_SECRET) as jwt.JwtPayload;
    req.user = { userId: payload.userId as string, role: payload.role as string };
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

/**
 * RBAC gate. Use after requireAuth: requireRole("REGISTRAR") only lets
 * requests through whose req.user.role is in the allowed list; everyone
 * else gets 403. requireAuth must run first so req.user is populated.
 */
export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: "Not authenticated" });
      return;
    }
    if (!roles.includes(req.user.role)) {
      res.status(403).json({ error: "Forbidden: insufficient role" });
      return;
    }
    next();
  };
}

// Machine-readable denial reasons for requireCertifiedRole() below. Only
// four, matching exactly what the spec asks for — a broken signature chain
// (forged, tampered, or signed by an unknown CA) is folded into
// CERT_REVOKED rather than given a fifth code, since the practical
// consequence for the caller is identical ("this certificate cannot be
// trusted right now") and that failure mode should never occur in practice
// outside of a direct database tamper.
export type CertifiedRoleDenialReason = "CERT_MISSING" | "CERT_REVOKED" | "CERT_EXPIRED" | "CERT_ROLE_MISMATCH";

function extractOuRole(certificatePem: string): string | null {
  const parsed = new x509.X509Certificate(certificatePem);
  const match = parsed.subject.match(/OU=([^,]+)/);
  return match ? match[1] : null;
}

/**
 * RBAC gate, bound to the caller's actual PKI identity, not just their
 * session's claimed role. Use after requireAuth, wherever requireRole()
 * was previously the gate on a state-changing or privileged endpoint:
 * requireCertifiedRole("REGISTRAR") requires, in order —
 *   1. a certificate exists for this account (CERT_MISSING otherwise),
 *   2. it is not revoked (CERT_REVOKED),
 *   3. it is within its validity window (CERT_EXPIRED),
 *   4. it genuinely chains to our Issuing CA — verifyCertificate()'s own
 *      signature/keyUsage checks (CERT_REVOKED; see the reason-code
 *      comment above for why this folds in here),
 *   5. the role embedded in the certificate's own OU (not just the DB
 *      row) matches the account's session role AND is one of the roles
 *      this endpoint allows (CERT_ROLE_MISMATCH).
 * Every denial is also logged to the audit chain (action ACCESS_DENIED)
 * before the response is sent — if that write fails, the request fails
 * too (propagated to the global error handler), the same "a silently
 * unlogged state change is worse than a failed request" rule lib/audit.ts
 * applies everywhere else in this codebase.
 */
export function requireCertifiedRole(...roles: string[]) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!req.user) {
      res.status(401).json({ error: "Not authenticated" });
      return;
    }
    const { userId, role: sessionRole } = req.user;

    async function deny(reason: CertifiedRoleDenialReason, message: string): Promise<void> {
      await appendAuditEntry({
        action: "ACCESS_DENIED",
        actorUserId: userId,
        entityType: "ACCESS",
        details: { endpoint: `${req.method} ${req.originalUrl}`, reason },
      });
      res.status(403).json({ error: message, reason });
    }

    const result = await verifyCertificateForUser(userId);
    if (!result) {
      await deny("CERT_MISSING", "No certificate is on file for this account.");
      return;
    }
    const { details } = result;

    if (details.revoked) {
      await deny(
        "CERT_REVOKED",
        `Certificate was revoked${details.revokedReason ? `: ${details.revokedReason}` : "."}`,
      );
      return;
    }
    if (!details.withinValidityWindow) {
      await deny(
        "CERT_EXPIRED",
        details.expired ? `Certificate expired on ${details.expiresAt}.` : "Certificate is not yet valid.",
      );
      return;
    }
    if (!details.userSignatureValid || !details.issuingSignatureValid || !details.keyUsageValid) {
      await deny("CERT_REVOKED", "Certificate does not chain to the Issuing CA and cannot be trusted.");
      return;
    }

    const certRow = await prisma.certificate.findUnique({
      where: { id: details.certificateId },
      select: { certificatePem: true },
    });
    const ouRole = certRow ? extractOuRole(certRow.certificatePem) : null;
    if (ouRole === null || ouRole !== sessionRole || !roles.includes(ouRole)) {
      await deny("CERT_ROLE_MISMATCH", "This certificate's role does not authorize this action.");
      return;
    }

    next();
  };
}
