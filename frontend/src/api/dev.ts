// api/dev.ts — DEMO-ONLY. Mirrors backend routes/dev.ts: calls the
// Registrar-only endpoint that simulates a database-level tamper,
// bypassing the app's signing flow entirely. Never used by any real
// user-facing flow — only the tamper demo button on LandRecordDetail.

import { api } from "./client";
import type { TransactionActionResult } from "../types";

export function tamperTransaction(transactionId: string) {
  return api.post<TransactionActionResult>(`/dev/tamper/${transactionId}`).then((r) => r.data);
}
