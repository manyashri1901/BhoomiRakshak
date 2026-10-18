import { api } from "./client";
import type {
  AutoRejectResult,
  MyTransaction,
  TransactionActionResult,
  TransactionType,
  TransactionVerifyResult,
  TransactionWithChain,
} from "../types";

export interface PreparedSignature {
  nonce: string;
  payload: string;
  payloadHash: string;
  expiresAt: string;
}

export interface CreateTransactionInput {
  type: TransactionType;
  landRecordId: string;
  toOwnerId?: string;
  documentPath: string;
  documentHash: string;
  // SUCCESSION's optional heir/legal document, alongside the required
  // death certificate (documentPath/documentHash above).
  secondaryDocumentPath?: string;
  secondaryDocumentHash?: string;
}

export function prepareCreateTransaction(input: CreateTransactionInput) {
  return api.post<PreparedSignature>("/transactions/prepare", input).then((r) => r.data);
}

export function submitCreateTransaction(nonce: string, signatureValue: string) {
  return api
    .post<TransactionActionResult>("/transactions/submit", { nonce, signatureValue })
    .then((r) => r.data);
}

/** Every transaction where the caller is the buyer or the seller, however
 * ownership currently stands — backs transfer-status visibility on both
 * the buyer's and seller's dashboards. */
export function getMyTransactions() {
  return api.get<MyTransaction[]>("/transactions/mine").then((r) => r.data);
}

export function listPendingVo() {
  return api.get<TransactionWithChain[]>("/transactions/pending-vo").then((r) => r.data);
}

export function listPendingRegistrar() {
  return api.get<TransactionWithChain[]>("/transactions/pending-registrar").then((r) => r.data);
}

export type ReviewResult = TransactionActionResult | AutoRejectResult;

export function prepareVoReview(id: string) {
  return api.post<PreparedSignature>(`/transactions/${id}/vo-review/prepare`).then((r) => r.data);
}

export function submitVoReview(id: string, nonce: string, signatureValue: string) {
  return api
    .post<ReviewResult>(`/transactions/${id}/vo-review/submit`, { nonce, signatureValue })
    .then((r) => r.data);
}

export function rejectVoReview(id: string, reason: string) {
  return api.post<ReviewResult>(`/transactions/${id}/vo-review/reject`, { reason }).then((r) => r.data);
}

export function prepareRegistrarReview(id: string) {
  return api.post<PreparedSignature>(`/transactions/${id}/registrar-review/prepare`).then((r) => r.data);
}

export function submitRegistrarReview(id: string, nonce: string, signatureValue: string) {
  return api
    .post<ReviewResult>(`/transactions/${id}/registrar-review/submit`, { nonce, signatureValue })
    .then((r) => r.data);
}

export function rejectRegistrarReview(id: string, reason: string) {
  return api
    .post<ReviewResult>(`/transactions/${id}/registrar-review/reject`, { reason })
    .then((r) => r.data);
}

export function isAutoReject(result: ReviewResult): result is AutoRejectResult {
  return "autoRejected" in result;
}

export function verifyTransaction(id: string) {
  return api.get<TransactionVerifyResult>(`/transactions/${id}/verify`).then((r) => r.data);
}
