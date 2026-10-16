// frontend/src/api/anchor.ts
//
// RFC 3161 audit-chain anchoring — ADMIN-only endpoints (routes/audit.ts).
// A small API helper file, same pattern as api/audit.ts, kept separate from
// it only so the audit card's existing imports don't need to change.

import { api } from "./client";

export interface AnchorSummary {
  id: string;
  headLogId: string;
  headSeq: number | null;
  headHash: string;
  tsaUrl: string;
  genTime: string;
  tsaSerial: string;
  policyOid: string;
  createdAt: string;
}

export type AnchorStatus = "VALID" | "TAMPERED" | "MISSING" | "TOKEN_INVALID";

export interface AnchorCheckStep {
  id: "tokenParses" | "messageImprint" | "cmsSignature" | "tsaCertificate" | "nonce" | "genTime" | "entryIntact" | "chainIntact";
  label: string;
  pass: boolean;
  detail: string;
}

export interface AnchorVerificationResult {
  anchorId: string;
  headLogId: string;
  tsaUrl: string;
  genTime: string;
  status: AnchorStatus;
  steps: AnchorCheckStep[];
}

export type AnchorAttemptResult =
  | { outcome: "anchored"; anchorId: string; headSeq: number; genTime: string }
  | { outcome: "skipped-too-soon"; nextEligibleAt: string }
  | { outcome: "skipped-empty-chain" }
  | { outcome: "failed"; reason: string };

export function getAnchors() {
  return api.get<{ anchors: AnchorSummary[] }>("/audit/anchors").then((r) => r.data.anchors);
}

export function verifyAnchors(limit?: number) {
  return api
    .get<{ results: AnchorVerificationResult[] }>("/audit/anchors/verify", { params: limit ? { limit } : undefined })
    .then((r) => r.data.results);
}

export function anchorNow() {
  return api.post<AnchorAttemptResult>("/audit/anchor").then((r) => r.data);
}
