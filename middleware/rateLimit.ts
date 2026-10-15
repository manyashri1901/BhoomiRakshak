// middleware/rateLimit.ts
//
// Login is rate-limited much more strictly than registration: it's the
// endpoint a credential-stuffing or brute-force script actually hits
// repeatedly, where registration failures are naturally self-limiting
// (each attempt consumes an email address). Both thresholds are
// env-configurable so a load test can raise them without a code change.

import { rateLimit, ipKeyGenerator } from "express-rate-limit";
import type { Request } from "express";

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function emailFromBody(req: Request): string {
  const email = (req.body as { email?: unknown } | undefined)?.email;
  return typeof email === "string" ? email.trim().toLowerCase() : "";
}

// Keyed by IP + the attempted email, not IP alone: one attacker hammering
// a single victim's account still gets capped quickly (their IP+email
// bucket fills), but it no longer locks every OTHER account on the same
// IP out of logging in too — which a pure-IP key would do on any shared
// IP (an office NAT, a campus network, or every tester on one dev
// machine, as happened while testing this). ipKeyGenerator() normalizes
// IPv6 addresses to a /56 subnet so rotating within one, and rate-limit's
// own validator doesn't warn about a raw req.ip bypass.
export const loginRateLimiter = rateLimit({
  windowMs: envInt("RATE_LIMIT_LOGIN_WINDOW_MS", 15 * 60 * 1000),
  limit: envInt("RATE_LIMIT_LOGIN_MAX", 10),
  standardHeaders: true,
  legacyHeaders: false,
  // A request that ends in a successful login (status < 400) doesn't count
  // against the budget at all — only failed attempts accumulate, so a user
  // who mistypes their password a few times before getting it right is
  // never locked out by their own eventual success.
  skipSuccessfulRequests: true,
  keyGenerator: (req) => `${ipKeyGenerator(req.ip ?? "")}:${emailFromBody(req)}`,
  message: { error: "Too many login attempts for this account. Please try again later." },
});

export const registerRateLimiter = rateLimit({
  windowMs: envInt("RATE_LIMIT_REGISTER_WINDOW_MS", 60 * 60 * 1000),
  limit: envInt("RATE_LIMIT_REGISTER_MAX", 20),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many registration attempts from this address. Please try again later." },
});

// Shared by every "directory-style" lookup endpoint — certificate lookup
// by serial, certificate name search, and the general user search/picker
// (/api/users) — all authenticated already, but each is still a
// repeatable, scriptable way to enumerate identities one request at a
// time, which login/register's own limiters above don't cover at all.
// Keyed by IP + the logged-in user id (not IP alone) so one authenticated
// account hammering this doesn't exhaust the budget for every other user
// behind the same IP (an office NAT, etc.) — same reasoning as
// loginRateLimiter's IP+email key.
export const directoryLookupRateLimiter = rateLimit({
  windowMs: envInt("RATE_LIMIT_DIRECTORY_WINDOW_MS", 60 * 1000),
  limit: envInt("RATE_LIMIT_DIRECTORY_MAX", 30),
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `${ipKeyGenerator(req.ip ?? "")}:${req.user?.userId ?? "anon"}`,
  message: { error: "Too many lookup requests. Please slow down and try again shortly." },
});
