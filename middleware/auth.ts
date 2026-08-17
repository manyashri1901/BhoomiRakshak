// middleware/auth.ts
//
// Session auth for the HTTP API. This is intentionally separate from the
// PKI layer in lib/ca.ts: JWTs here only prove "this request came from a
// logged-in session for user X with role Y" to the Express app. They are
// never used to sign land records, transactions, or certificates — that
// trust chain runs entirely through each user's RSA keypair and the CA.

import jwt from "jsonwebtoken";
import type { NextFunction, Request, Response } from "express";

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
