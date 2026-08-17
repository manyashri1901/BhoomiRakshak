import { api } from "./client";
import type {
  AutoRejectResult,
  TransactionActionResult,
  TransactionType,
  TransactionVerifyResult,
  TransactionWithChain,
} from "../types";

export interface CreateTransactionInput {
  type: TransactionType;
  landRecordId: string;
  toOwnerId?: string;
  documentPath: string;
  documentHash: string;
}

export function createTransaction(input: CreateTransactionInput) {
  return api.post<TransactionActionResult>("/transactions", input).then((r) => r.data);
}

export function listPendingVo() {
  return api.get<TransactionWithChain[]>("/transactions/pending-vo").then((r) => r.data);
}

export function listPendingRegistrar() {
  return api.get<TransactionWithChain[]>("/transactions/pending-registrar").then((r) => r.data);
}

export type ReviewResult = TransactionActionResult | AutoRejectResult;

export function reviewAsVo(id: string, decision: "APPROVE" | "REJECT", reason?: string) {
  return api
    .post<ReviewResult>(`/transactions/${id}/vo-review`, { decision, reason })
    .then((r) => r.data);
}

export function reviewAsRegistrar(id: string, decision: "APPROVE" | "REJECT", reason?: string) {
  return api
    .post<ReviewResult>(`/transactions/${id}/registrar-review`, { decision, reason })
    .then((r) => r.data);
}

export function isAutoReject(result: ReviewResult): result is AutoRejectResult {
  return "autoRejected" in result;
}

export function verifyTransaction(id: string) {
  return api.get<TransactionVerifyResult>(`/transactions/${id}/verify`).then((r) => r.data);
}
