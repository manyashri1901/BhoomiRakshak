// middleware/rateLimit.ts
//
// Login is rate-limited much more strictly than registration: it's the
// endpoint a credential-stuffing or brute-force script actually hits
// repeatedly, where registration failures are naturally self-limiting
// (each attempt consumes an email address). Both thresholds are
// env-configurable so a load test can raise them without a code change.

import { rateLimit } from "express-rate-limit";

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export const loginRateLimiter = rateLimit({
  windowMs: envInt("RATE_LIMIT_LOGIN_WINDOW_MS", 15 * 60 * 1000),
  limit: envInt("RATE_LIMIT_LOGIN_MAX", 5),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts. Please try again later." },
});

export const registerRateLimiter = rateLimit({
  windowMs: envInt("RATE_LIMIT_REGISTER_WINDOW_MS", 60 * 60 * 1000),
  limit: envInt("RATE_LIMIT_REGISTER_MAX", 20),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many registration attempts from this address. Please try again later." },
});
