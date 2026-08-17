import { useCallback, useEffect, useState } from "react";
import axios from "axios";
import { listPendingVo, reviewAsVo } from "../api/transactions";
import { ReviewQueue } from "../components/ReviewQueue";
import type { TransactionWithChain } from "../types";

export function VillageOfficerDashboard() {
  const [transactions, setTransactions] = useState<TransactionWithChain[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const load = useCallback(() => {
    listPendingVo()
      .then(setTransactions)
      .catch((err) => {
        setLoadError(
          axios.isAxiosError(err)
            ? (err.response?.data?.error ?? "Failed to load review queue")
            : "Failed to load review queue",
        );
      });
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="font-serif text-2xl font-semibold text-ink">Review Queue</h1>
        <p className="mt-1 text-sm text-muted">
          Transactions pending your review. The landowner's signature is verified live before any
          decision is recorded.
        </p>
      </div>

      <ReviewQueue
        title="Pending Village Officer review"
        description="Select a transaction to inspect its document and the landowner's signature before deciding."
        transactions={transactions}
        loadError={loadError}
        emptyLabel="No pending transactions."
        onApprove={(id) => reviewAsVo(id, "APPROVE")}
        onReject={(id, reason) => reviewAsVo(id, "REJECT", reason)}
        onDecided={load}
      />
    </div>
  );
}
