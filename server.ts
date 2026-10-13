// server.ts — BhoomiRakshak API entrypoint.

import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import type { NextFunction, Request, Response } from "express";
import authRouter from "./routes/auth.ts";
import documentsRouter from "./routes/documents.ts";
import landRecordsRouter from "./routes/land-records.ts";
import transactionsRouter from "./routes/transactions.ts";
import certificatesRouter from "./routes/certificates.ts";
import usersRouter from "./routes/users.ts";
import auditRouter from "./routes/audit.ts";
import devRouter from "./routes/dev.ts";
import { requireAuth, requireRole } from "./middleware/auth.ts";

const app = express();

// Rate limiting and anything else keyed by req.ip only sees the real
// client address if Express knows to read it from X-Forwarded-For rather
// than using the connecting socket's address — which, behind a host like
// Render, is the platform's own reverse proxy, not the client. Trusting
// that header blindly would let a client forge their own IP, so this is
// opt-in and explicit: TRUST_PROXY unset defaults to 1 (trust exactly one
// hop) in production, where there IS always exactly one reverse proxy in
// front of this process, and to false in development, where there is no
// proxy and nothing should be trusted to supply a fake client IP.
// TRUST_PROXY accepts "true"/"false", a hop count (e.g. "1"), or any
// string express's own `trust proxy` setting understands (e.g. "loopback").
function resolveTrustProxy(): boolean | number | string {
  const raw = process.env.TRUST_PROXY;
  if (raw === undefined) {
    return process.env.NODE_ENV === "production" ? 1 : false;
  }
  if (raw === "true") return true;
  if (raw === "false") return false;
  const asNumber = Number(raw);
  return Number.isFinite(asNumber) ? asNumber : raw;
}
app.set("trust proxy", resolveTrustProxy());

app.use(helmet());

// The frontend (Vite dev server) runs on a different origin, so the
// browser needs an explicit CORS allow — auth is via a Bearer token in the
// Authorization header, not cookies, so no credentials flag is needed.
app.use(
  cors({
    origin: process.env.FRONTEND_ORIGIN ?? "http://localhost:5173",
  }),
);
app.use(express.json());

app.use("/api/auth", authRouter);
app.use("/api/documents", documentsRouter);
app.use("/api/land-records", landRecordsRouter);
app.use("/api/transactions", transactionsRouter);
app.use("/api/certificates", certificatesRouter);
app.use("/api/users", usersRouter);
app.use("/api/audit", auditRouter);

// DEMO-ONLY, and only when explicitly opted into — see routes/dev.ts. Not
// mounting the router at all (rather than mounting it and gating inside)
// means every /api/dev/* request 404s exactly like any other unknown
// route when this flag isn't set, with no trace that the route exists.
if (process.env.ENABLE_DEMO_TAMPER === "true") {
  app.use("/api/dev", devRouter);
}

// Protected test route (Step 4): only a logged-in Registrar can reach this.
app.get(
  "/api/test/registrar-only",
  requireAuth,
  requireRole("REGISTRAR"),
  (req: Request, res: Response) => {
    res.json({ message: "Welcome, Registrar.", user: req.user });
  },
);

// Falls through to Express's default handling for anything unmatched;
// this only catches thrown/rejected errors from the routes above.
app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

const PORT = process.env.PORT ? Number(process.env.PORT) : 4000;
app.listen(PORT, () => {
  console.log(`BhoomiRakshak API listening on http://localhost:${PORT}`);
});
