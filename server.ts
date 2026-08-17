// server.ts — BhoomiRakshak API entrypoint.

import "dotenv/config";
import express from "express";
import cors from "cors";
import type { NextFunction, Request, Response } from "express";
import authRouter from "./routes/auth.ts";
import documentsRouter from "./routes/documents.ts";
import landRecordsRouter from "./routes/land-records.ts";
import transactionsRouter from "./routes/transactions.ts";
import certificatesRouter from "./routes/certificates.ts";
import usersRouter from "./routes/users.ts";
import devRouter from "./routes/dev.ts";
import { requireAuth, requireRole } from "./middleware/auth.ts";

const app = express();

// The frontend (Vite dev server) runs on a different origin, so the
// browser needs an explicit CORS allow — auth is via a Bearer token in the
// Authorization header, not cookies, so no credentials flag is needed.
app.use(
  cors({
    origin: process.env.FRONTEND_URL ?? "http://localhost:5173",
  }),
);
app.use(express.json());

app.use("/api/auth", authRouter);
app.use("/api/documents", documentsRouter);
app.use("/api/land-records", landRecordsRouter);
app.use("/api/transactions", transactionsRouter);
app.use("/api/certificates", certificatesRouter);
app.use("/api/users", usersRouter);
app.use("/api/dev", devRouter); // DEMO-ONLY — see routes/dev.ts

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
