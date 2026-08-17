import { useCallback, useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import axios from "axios";
import { getLandRecordHistory } from "../api/landRecords";
import { tamperTransaction } from "../api/dev";
import { formatAreaWithConversion } from "../lib/areaUnits";
import { Card } from "../components/Card";
import { LandRecordStatusBadge, TransactionStatusBadge } from "../components/StatusBadge";
import { ValidBadge } from "../components/ValidBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { useAuth } from "../context/AuthContext";
import type { HistoryTransaction, LandRecordHistory } from "../types";

const ROLE_LABELS: Record<string, string> = {
  LANDOWNER: "Landowner",
  VILLAGE_OFFICER: "Village Officer",
  REGISTRAR: "Registrar",
};

function formatDateTime(iso: string) {
  return new Date(iso).toLocaleString();
}

interface TransactionCardProps {
  transaction: HistoryTransaction;
  canTamper: boolean;
  onTampered: () => void;
}

function TransactionCard({ transaction, canTamper, onTampered }: TransactionCardProps) {
  const [tampering, setTampering] = useState(false);
  const [tamperError, setTamperError] = useState<string | null>(null);

  const anySignatureInvalid = transaction.signatures.some((s) => !s.valid);
  const documentMismatch = !transaction.documentIntegrity.match;
  const isTampered = anySignatureInvalid || documentMismatch;

  async function handleTamper() {
    setTampering(true);
    setTamperError(null);
    try {
      await tamperTransaction(transaction.id);
      onTampered();
    } catch (err) {
      setTamperError(
        axios.isAxiosError(err) ? (err.response?.data?.error ?? "Tamper failed") : "Tamper failed",
      );
    } finally {
      setTampering(false);
    }
  }

  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="font-medium text-ink">{transaction.type}</span>
          <TransactionStatusBadge status={transaction.status} />
        </div>
        <span className="text-xs text-muted">{formatDateTime(transaction.createdAt)}</span>
      </div>

      {transaction.rejectReason && (
        <p className="mt-2 rounded-md bg-danger-chip px-3 py-2 text-sm text-wax-seal">
          Rejected: {transaction.rejectReason}
        </p>
      )}

      {isTampered && (
        <div className="mt-3 rounded-md border border-wax-seal bg-danger-chip px-4 py-3 text-sm text-wax-seal">
          <p className="font-semibold">⚠ Tamper detected</p>
          <p className="mt-1">
            {documentMismatch
              ? "Document hash no longer matches stored signature — this record has been tampered with after approval."
              : "A signature in this transaction's chain no longer verifies against the stored data."}
          </p>
        </div>
      )}

      <div className="mt-4 flex items-center justify-between rounded-md bg-neutral-chip px-3 py-2 text-sm">
        <span className="text-ink">Document integrity</span>
        <ValidBadge
          valid={transaction.documentIntegrity.match}
          label={transaction.documentIntegrity.match ? "Matches on disk" : "Mismatch"}
        />
      </div>

      <ol className="mt-4 flex flex-col gap-3 border-l-2 border-camel pl-4">
        {transaction.signatures.map((sig, i) => (
          <li key={i} className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <span className="text-sm font-medium text-ink">{sig.actorName}</span>
              <span className="ml-2 text-xs uppercase tracking-wide text-muted">
                {ROLE_LABELS[sig.role] ?? sig.role}
              </span>
              <div className="text-xs text-muted">{formatDateTime(sig.signedAt)}</div>
            </div>
            <ValidBadge valid={sig.valid} />
          </li>
        ))}
      </ol>

      {canTamper && transaction.status === "APPROVED" && (
        <div className="mt-4 border-t border-border-subtle pt-3">
          {tamperError && (
            <p className="mb-2 rounded-md bg-danger-chip px-3 py-2 text-sm text-wax-seal">
              {tamperError}
            </p>
          )}
          <button
            type="button"
            onClick={handleTamper}
            disabled={tampering}
            className="rounded-md border border-wax-seal px-3 py-1.5 text-sm font-medium text-wax-seal hover:bg-danger-chip disabled:cursor-not-allowed disabled:opacity-60"
          >
            {tampering ? "Tampering…" : "Simulate Tamper (Demo)"}
          </button>
          <p className="mt-1 text-xs text-muted">
            Demo only — directly overwrites the stored document hash in the database, bypassing
            the signing flow entirely, to prove verification catches it.
          </p>
        </div>
      )}
    </Card>
  );
}

export function LandRecordDetail() {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const [data, setData] = useState<LandRecordHistory | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    if (!id) return;
    getLandRecordHistory(id)
      .then(setData)
      .catch((err) => {
        setError(
          axios.isAxiosError(err)
            ? (err.response?.data?.error ?? "Failed to load land record")
            : "Failed to load land record",
        );
      });
  }, [id]);

  useEffect(() => {
    setData(null);
    setError(null);
    load();
  }, [load]);

  if (error) return <ErrorState label={error} />;
  if (!data) return <LoadingState label="Loading land record…" />;

  const { landRecord, transactions } = data;

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="font-serif text-2xl font-semibold text-ink">
              Survey No. {landRecord.surveyNumber}
            </h1>
            <p className="mt-1 text-sm text-muted">{landRecord.location}</p>
          </div>
          <LandRecordStatusBadge status={landRecord.status} />
        </div>
        <dl className="mt-4 grid grid-cols-2 gap-4 text-sm sm:grid-cols-3">
          <div>
            <dt className="text-muted">Area</dt>
            <dd className="text-ink">{formatAreaWithConversion(landRecord.area, landRecord.areaUnit)}</dd>
          </div>
          <div>
            <dt className="text-muted">Registered</dt>
            <dd className="text-ink">{formatDateTime(landRecord.createdAt)}</dd>
          </div>
        </dl>
      </Card>

      <div>
        <h2 className="font-serif text-lg font-semibold text-ink">Transaction history</h2>
        <p className="mt-1 text-sm text-muted">
          Every signature below is re-verified live against the actor's stored public key, and the
          document hash is independently recomputed from disk — this is the tamper-evident audit
          trail, not a cached status.
        </p>
      </div>

      {transactions.length === 0 && (
        <EmptyState label="No transactions have been recorded against this land record yet." />
      )}

      <div className="flex flex-col gap-4">
        {transactions.map((transaction) => (
          <TransactionCard
            key={transaction.id}
            transaction={transaction}
            canTamper={user?.role === "REGISTRAR"}
            onTampered={load}
          />
        ))}
      </div>
    </div>
  );
}
