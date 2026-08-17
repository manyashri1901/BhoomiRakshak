import { Badge } from "./Badge";
import type { LandRecordStatus, TransactionStatus } from "../types";

const LAND_RECORD_VARIANT: Record<LandRecordStatus, "success" | "warning" | "danger" | "neutral"> = {
  ACTIVE: "success",
  PENDING: "warning",
  DISPUTED: "danger",
  TRANSFERRED: "neutral",
};

const TRANSACTION_VARIANT: Record<TransactionStatus, "success" | "warning" | "danger"> = {
  PENDING_VO: "warning",
  PENDING_REGISTRAR: "warning",
  APPROVED: "success",
  REJECTED: "danger",
};

const TRANSACTION_LABEL: Record<TransactionStatus, string> = {
  PENDING_VO: "Pending VO",
  PENDING_REGISTRAR: "Pending Registrar",
  APPROVED: "Approved",
  REJECTED: "Rejected",
};

export function LandRecordStatusBadge({ status }: { status: LandRecordStatus }) {
  return <Badge variant={LAND_RECORD_VARIANT[status]}>{status}</Badge>;
}

export function TransactionStatusBadge({ status }: { status: TransactionStatus }) {
  return <Badge variant={TRANSACTION_VARIANT[status]}>{TRANSACTION_LABEL[status]}</Badge>;
}
