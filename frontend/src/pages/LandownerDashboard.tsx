import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import axios from "axios";
import { CheckCircle2, Clock, Landmark, Upload } from "lucide-react";
import { listLandRecords, getLandRecordHistory } from "../api/landRecords";
import { prepareCreateTransaction, submitCreateTransaction } from "../api/transactions";
import { uploadDocument } from "../api/documents";
import { signAndSubmit } from "../lib/signAndSubmit";
import { useAuth } from "../context/AuthContext";
import { formatAreaWithConversion } from "../lib/areaUnits";
import { Card } from "../components/Card";
import { LandRecordStatusBadge, TransactionStatusBadge } from "../components/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { UserPicker } from "../components/UserPicker";
import { PasswordPrompt } from "../components/PasswordPrompt";
import { PageHeader } from "../components/ui/PageHeader";
import { StatCard } from "../components/ui/StatCard";
import { Button } from "../components/ui/Button";
import { Banner } from "../components/ui/Banner";
import { Field, fieldInputClasses } from "../components/ui/Field";
import { SkeletonTableRows } from "../components/ui/Skeleton";
import type { HistoryTransaction, LandRecordListItem, TransactionType, UserSummary } from "../types";

interface OwnedTransaction extends HistoryTransaction {
  surveyNumber: string;
}

const TYPES: TransactionType[] = ["REGISTRATION", "TRANSFER", "UPDATE"];

export function LandownerDashboard() {
  const { wrappedKey } = useAuth();
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

  // Set once the document is uploaded and the form is otherwise valid —
  // opening the password prompt is what actually triggers prepare -> sign
  // -> submit (lib/signAndSubmit.ts) against this input.
  const [pendingInput, setPendingInput] = useState<{
    type: TransactionType;
    landRecordId: string;
    toOwnerId?: string;
    documentPath: string;
    documentHash: string;
  } | null>(null);
  const [signingOpen, setSigningOpen] = useState(false);

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

  const stats = useMemo(() => {
    const pending = transactions?.filter((t) => t.status === "PENDING_VO" || t.status === "PENDING_REGISTRAR").length ?? 0;
    const approved = transactions?.filter((t) => t.status === "APPROVED").length ?? 0;
    return { total: records?.length ?? 0, pending, approved };
  }, [records, transactions]);

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
      setPendingInput({
        type,
        landRecordId,
        toOwnerId: type === "TRANSFER" ? toOwner!.id : undefined,
        documentPath: upload.documentPath,
        documentHash: upload.documentHash,
      });
      setSigningOpen(true);
    } catch (err) {
      setFormError(
        axios.isAxiosError(err)
          ? (err.response?.data?.error ?? "Failed to upload document")
          : "Failed to upload document",
      );
    } finally {
      setSubmitting(false);
    }
  }

  async function handleSignAndSubmit(password: string) {
    if (!pendingInput) return;
    if (!wrappedKey) {
      throw new Error("No signing key on this account — log out and back in, or re-register.");
    }
    await signAndSubmit(
      wrappedKey,
      password,
      () => prepareCreateTransaction(pendingInput),
      (nonce, signatureValue) => submitCreateTransaction(nonce, signatureValue),
    );
    setSigningOpen(false);
    setSuccessMessage("Transaction created and sent for Village Officer review.");
    setLandRecordId("");
    setType("REGISTRATION");
    setToOwner(null);
    setFile(null);
    setPendingInput(null);
    await loadData();
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title="My Land" subtitle="Your registered land parcels and their transaction activity." />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard label="Land records" value={stats.total} icon={Landmark} tone="navy" />
        <StatCard label="Pending review" value={stats.pending} icon={Clock} tone="warning" />
        <StatCard label="Approved" value={stats.approved} icon={CheckCircle2} tone="success" />
      </div>

      {loadError && <ErrorState label={loadError} />}

      {!loadError && records !== null && records.length === 0 && (
        <EmptyState label="Your land parcels will appear here once a Registrar registers them to you." />
      )}

      {!loadError && (records === null || records.length > 0) && (
        <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm">
          <table className="w-full min-w-160 border-collapse text-left text-sm">
            <thead className="sticky top-16 z-10">
              <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium uppercase tracking-wide text-slate-600">
                <th className="px-4 py-3">Survey No.</th>
                <th className="px-4 py-3">Location</th>
                <th className="px-4 py-3">Area</th>
                <th className="px-4 py-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {records === null && <SkeletonTableRows rows={3} columns={4} />}
              {records?.map((r) => (
                <tr key={r.id} className="border-b border-slate-100 last:border-0 hover:bg-slate-50">
                  <td className="px-4 py-3">
                    <Link to={`/land-records/${r.id}`} className="font-medium text-navy underline">
                      {r.surveyNumber}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-slate-700">{r.location}</td>
                  <td className="px-4 py-3 text-slate-700">{formatAreaWithConversion(r.area, r.areaUnit)}</td>
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
          <h2 className="text-lg font-semibold text-slate-900">Create Transaction</h2>
          <p className="mt-1 text-sm text-slate-600">
            Registers, transfers, or updates a land record you own. Sent for Village Officer review first.
          </p>

          <form onSubmit={handleSubmit} className="mt-4 flex flex-col gap-4">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field label="Land record">
                <select
                  value={landRecordId}
                  onChange={(e) => setLandRecordId(e.target.value)}
                  className={fieldInputClasses}
                >
                  <option value="">Select a land record…</option>
                  {records.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.surveyNumber} — {r.location}
                    </option>
                  ))}
                </select>
              </Field>

              <Field label="Transaction type">
                <select
                  value={type}
                  onChange={(e) => {
                    setType(e.target.value as TransactionType);
                    setToOwner(null);
                  }}
                  className={fieldInputClasses}
                >
                  {TYPES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </Field>
            </div>

            {type === "TRANSFER" && (
              <Field label="New owner">
                <UserPicker role="LANDOWNER" selected={toOwner} onSelect={setToOwner} placeholder="Search landowners by name…" />
              </Field>
            )}

            <Field label="Supporting document">
              <input
                type="file"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                className={`${fieldInputClasses} file:mr-3 file:rounded-md file:border-0 file:bg-slate-100 file:px-3 file:py-1 file:text-sm file:font-medium file:text-slate-700`}
              />
            </Field>

            {formError && <Banner variant="danger">{formError}</Banner>}
            {successMessage && <Banner variant="success">{successMessage}</Banner>}

            <Button type="submit" loading={submitting} icon={<Upload className="h-4 w-4" aria-hidden="true" />} className="self-start">
              {submitting ? "Uploading…" : "Continue to Sign"}
            </Button>
          </form>
        </Card>
      )}

      <div>
        <h2 className="text-lg font-semibold text-slate-900">Your transactions</h2>
        {transactions === null && !loadError && (
          <div className="mt-3">
            <LoadingState label="Loading transactions…" />
          </div>
        )}
        {transactions !== null && transactions.length === 0 && (
          <div className="mt-3">
            <EmptyState label="No pending transactions." />
          </div>
        )}
        {transactions !== null && transactions.length > 0 && (
          <div className="mt-3 flex flex-col gap-2">
            {transactions.map((t) => (
              <Link
                key={t.id}
                to={`/land-records/${t.landRecordId}`}
                className="flex items-center justify-between rounded-lg border border-slate-200 bg-white px-4 py-3 text-sm hover:bg-slate-50"
              >
                <span>
                  <span className="font-medium text-slate-900">{t.type}</span>
                  <span className="ml-2 text-slate-500">Survey No. {t.surveyNumber}</span>
                </span>
                <TransactionStatusBadge status={t.status} />
              </Link>
            ))}
          </div>
        )}
      </div>

      <PasswordPrompt
        open={signingOpen}
        title="Sign transaction"
        description="Enter your password to unlock your signing key and submit this transaction."
        confirmLabel="Sign & Submit"
        onConfirm={handleSignAndSubmit}
        onCancel={() => setSigningOpen(false)}
      />
    </div>
  );
}
