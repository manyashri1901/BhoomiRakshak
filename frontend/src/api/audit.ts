import { api } from "./client";

export interface AuditVerificationResult {
  valid: boolean;
  checked: number;
  firstBrokenSeq: number | null;
  reason: string | null;
}

export interface AuditChainHead {
  seq: number;
  hash: string | null;
}

export function verifyAuditChain() {
  return api.get<AuditVerificationResult>("/audit/verify").then((r) => r.data);
}

export function getAuditHead() {
  return api.get<AuditChainHead>("/audit/head").then((r) => r.data);
}

// Smallest possible page just to read `total` — the UI only needs the
// entry count, not the entries themselves, so pageSize:1 avoids pulling
// the whole log just to show a number.
export function getAuditEntryCount() {
  return api
    .get<{ total: number }>("/audit", { params: { page: 1, pageSize: 1 } })
    .then((r) => r.data.total);
}
