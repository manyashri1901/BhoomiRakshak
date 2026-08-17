import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import axios from "axios";
import { listLandRecords, getLandRecordHistory } from "../api/landRecords";
import { createTransaction } from "../api/transactions";
import { uploadDocument } from "../api/documents";
import { formatAreaWithConversion } from "../lib/areaUnits";
import { Card } from "../components/Card";
import { LandRecordStatusBadge, TransactionStatusBadge } from "../components/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { UserPicker } from "../components/UserPicker";
import type { HistoryTransaction, LandRecordListItem, TransactionType, UserSummary } from "../types";

interface OwnedTransaction extends HistoryTransaction {
  surveyNumber: string;
}

const TYPES: TransactionType[] = ["REGISTRATION", "TRANSFER", "UPDATE"];

export function LandownerDashboard() {
  const [records, setRecords] = useState<LandRecordListItem[] | null>(null);
  const [transactions, setTransactions] = useState<OwnedTransaction[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [landRecordId, setLandRecordId] = useState("");
  const [type, setType] = useState<TransactionType>("REGISTRATION");
  const [toOwner, setToOwner] = useState<UserSummary | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Guards the second wave of requests below (per-record history fetches)
  // from firing after this component has unmounted — e.g. the user logs
  // out while the initial load is still between its two awaits. Without
  // this, those requests get dispatched with no auth token (already
  // cleared by logout) and 401, harmlessly but needlessly.
  const mountedRef = useRef(true);

  async function loadData() {
    try {
      const recordList = await listLandRecords();
      if (!mountedRef.current) return;
      setRecords(recordList);
      const histories = await Promise.all(recordList.map((r) => getLandRecordHistory(r.id)));
      if (!mountedRef.current) return;
      const merged: OwnedTransaction[] = histories.flatMap((h) =>
        h.transactions.map((t) => ({ ...t, surveyNumber: h.landRecord.surveyNumber })),
      );
      merged.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
      setTransactions(merged);
    } catch (err) {
      if (!mountedRef.current) return;
      setLoadError(
        axios.isAxiosError(err)
          ? (err.response?.data?.error ?? "Failed to load your land records")
          : "Failed to load your land records",
      );
    }
  }

  useEffect(() => {
    mountedRef.current = true;
    loadData();
    return () => {
      mountedRef.current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setFormError(null);
    setSuccessMessage(null);

    if (!landRecordId) {
      setFormError("Select a land record.");
      return;
    }
    if (type === "TRANSFER" && !toOwner) {
      setFormError("Select the new owner for a transfer.");
      return;
    }
    if (!file) {
      setFormError("Attach a supporting document.");
      return;
    }

    setSubmitting(true);
    try {
      const upload = await uploadDocument(file);
      await createTransaction({
        type,
        landRecordId,
        toOwnerId: type === "TRANSFER" ? toOwner!.id : undefined,
        documentPath: upload.documentPath,
        documentHash: upload.documentHash,
      });
      setSuccessMessage("Transaction created and sent for Village Officer review.");
      setLandRecordId("");
      setType("REGISTRATION");
      setToOwner(null);
      setFile(null);
      await loadData();
    } catch (err) {
      setFormError(
        axios.isAxiosError(err)
          ? (err.response?.data?.error ?? "Failed to create transaction")
          : "Failed to create transaction",
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="font-serif text-2xl font-semibold text-ink">My Land</h1>
        <p className="mt-1 text-sm text-muted">Your registered land parcels and their transaction activity.</p>
      </div>

      {loadError && <ErrorState label={loadError} />}

      {!loadError && records === null && <LoadingState label="Loading your land records…" />}

      {!loadError && records !== null && records.length === 0 && (
        <EmptyState label="No land records are registered under your name yet. A Registrar must create one first." />
      )}

      {!loadError && records !== null && records.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-border-subtle bg-surface shadow-sm">
          <table className="w-full min-w-160 border-collapse text-left text-sm">
            <thead>
              <tr className="border-b border-border-subtle bg-neutral-chip text-xs font-medium uppercase tracking-wide text-ink">
                <th className="px-4 py-3">Survey No.</th>
                <th className="px-4 py-3">Location</th>
                <th className="px-4 py-3">Area</th>
                <th className="px-4 py-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {records.map((r) => (
                <tr key={r.id} className="border-b border-border-subtle last:border-0 hover:bg-neutral-chip">
                  <td className="px-4 py-3">
                    <Link to={`/land-records/${r.id}`} className="font-medium text-ink underline">
                      {r.surveyNumber}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-ink">{r.location}</td>
                  <td className="px-4 py-3 text-ink">{formatAreaWithConversion(r.area, r.areaUnit)}</td>
                  <td className="px-4 py-3">
                    <LandRecordStatusBadge status={r.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {records && records.length > 0 && (
        <Card>
          <h2 className="font-serif text-lg font-semibold text-ink">Create Transaction</h2>
          <p className="mt-1 text-sm text-muted">
            Registers, transfers, or updates a land record you own. Sent for Village Officer review first.
          </p>

          <form onSubmit={handleSubmit} className="mt-4 flex flex-col gap-4">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <label className="flex flex-col gap-1">
                <span className="text-sm font-medium text-ink">Land record</span>
                <select
                  value={landRecordId}
                  onChange={(e) => setLandRecordId(e.target.value)}
                  className="rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm outline-none focus:border-camel focus:ring-1 focus:ring-camel"
                >
                  <option value="">Select a land record…</option>
                  {records.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.surveyNumber} — {r.location}
                    </option>
                  ))}
                </select>
              </label>

              <label className="flex flex-col gap-1">
                <span className="text-sm font-medium text-ink">Transaction type</span>
                <select
                  value={type}
                  onChange={(e) => {
                    setType(e.target.value as TransactionType);
                    setToOwner(null);
                  }}
                  className="rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm outline-none focus:border-camel focus:ring-1 focus:ring-camel"
                >
                  {TYPES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            {type === "TRANSFER" && (
              <label className="flex flex-col gap-1">
                <span className="text-sm font-medium text-ink">New owner</span>
                <UserPicker role="LANDOWNER" selected={toOwner} onSelect={setToOwner} placeholder="Search landowners by name…" />
              </label>
            )}

            <label className="flex flex-col gap-1">
              <span className="text-sm font-medium text-ink">Supporting document</span>
              <input
                type="file"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                className="rounded-md border border-border-subtle px-3 py-2 text-sm file:mr-3 file:rounded file:border-0 file:bg-neutral-chip file:px-3 file:py-1 file:text-sm file:font-medium file:text-ink"
              />
            </label>

            {formError && <ErrorState label={formError} />}
            {successMessage && (
              <p className="rounded-md bg-valid-chip px-3 py-2 text-sm text-dark-cocoa">{successMessage}</p>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="self-start rounded-md bg-coffee px-4 py-2 text-sm font-semibold text-apricot hover:bg-coffee-hover disabled:cursor-not-allowed disabled:opacity-60"
            >
              {submitting ? "Submitting…" : "Create Transaction"}
            </button>
          </form>
        </Card>
      )}

      <div>
        <h2 className="font-serif text-lg font-semibold text-ink">Your transactions</h2>
        {transactions === null && !loadError && <LoadingState label="Loading transactions…" />}
        {transactions !== null && transactions.length === 0 && (
          <EmptyState label="No pending transactions." />
        )}
        {transactions !== null && transactions.length > 0 && (
          <div className="mt-3 flex flex-col gap-2">
            {transactions.map((t) => (
              <Link
                key={t.id}
                to={`/land-records/${t.landRecordId}`}
                className="flex items-center justify-between rounded-md border border-border-subtle bg-surface px-4 py-3 text-sm hover:bg-neutral-chip"
              >
                <span>
                  <span className="font-medium text-ink">{t.type}</span>
                  <span className="ml-2 text-muted">Survey No. {t.surveyNumber}</span>
                </span>
                <TransactionStatusBadge status={t.status} />
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
