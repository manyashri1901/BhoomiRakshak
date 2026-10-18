import { useCallback, useEffect, useState } from "react";
import { ClipboardList } from "lucide-react";
import { listPendingVo, prepareVoReview, submitVoReview, rejectVoReview } from "../api/transactions";
import { ReviewQueue } from "../components/ReviewQueue";
import { PageHeader } from "../components/ui/PageHeader";
import { StatCard } from "../components/ui/StatCard";
import { getErrorMessage } from "../lib/errorMessage";
import type { TransactionWithChain } from "../types";

export function VillageOfficerDashboard() {
  const [transactions, setTransactions] = useState<TransactionWithChain[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const load = useCallback(() => {
    listPendingVo()
      .then(setTransactions)
      .catch((err) => {
        setLoadError(getErrorMessage(err, "Failed to load review queue"));
      });
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Review Queue"
        subtitle="Transactions pending your review. The landowner's signature is verified live before any decision is recorded."
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard label="Pending your review" value={transactions?.length ?? 0} icon={ClipboardList} tone="warning" />
      </div>

      <ReviewQueue
        title="Pending Village Officer review"
        description="Select a transaction to inspect its document and the landowner's signature before deciding."
        transactions={transactions}
        loadError={loadError}
        emptyLabel="No pending transactions."
        prepareApprove={prepareVoReview}
        submitApprove={submitVoReview}
        onReject={rejectVoReview}
        onDecided={load}
      />
    </div>
  );
}
