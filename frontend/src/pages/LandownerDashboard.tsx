import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, Clock, HeartHandshake, Landmark, Upload } from "lucide-react";
import { listLandRecords } from "../api/landRecords";
import { prepareCreateTransaction, submitCreateTransaction, getMyTransactions } from "../api/transactions";
import { uploadDocument } from "../api/documents";
import { signAndSubmit } from "../lib/signAndSubmit";
import { getErrorMessage } from "../lib/errorMessage";
import { useAuth } from "../context/AuthContext";
import { Card } from "../components/Card";
import { LandRecordsTable } from "../components/LandRecordsTable";
import { TransactionStatusBadge } from "../components/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { PasswordPrompt } from "../components/PasswordPrompt";
import { TransferOwnershipModal } from "../components/TransferOwnershipModal";
import { ClaimHeirModal } from "../components/ClaimHeirModal";
import { PageHeader } from "../components/ui/PageHeader";
import { StatCard } from "../components/ui/StatCard";
import { Button } from "../components/ui/Button";
import { Banner } from "../components/ui/Banner";
import { Field, fieldInputClasses } from "../components/ui/Field";
import type { LandRecordListItem, MyTransaction, TransactionType } from "../types";

// TRANSFER is deliberately excluded — ownership transfers now go through
// the per-record "Transfer ownership" button (LandRecordsTable /
// TransferOwnershipModal), not this generic multi-type form. REGISTRATION
// and UPDATE never change hands (toOwnerId is always the caller
// themselves), so they're unaffected by that move.
const TYPES: TransactionType[] = ["REGISTRATION", "UPDATE"];

// A buyer/heir on a still-pending (or rejected) incoming transfer or
// succession claim doesn't own the land record yet, so
// GET /land-records/:id/history 404s for them — the detail page simply
// isn't viewable until ownership actually moves. Mirrors exactly when
// routes/transactions.ts's registrar-review/submit updates currentOwnerId:
// only on an APPROVED TRANSFER or SUCCESSION (REGISTRATION/UPDATE never
// change hands — toOwnerId is already the caller themselves).
function currentlyOwnedByUser(t: MyTransaction, userId: string): boolean {
  const changesOwnerOnApproval = t.type === "TRANSFER" || t.type === "SUCCESSION";
  const effectiveOwnerId =
    changesOwnerOnApproval && t.status === "APPROVED" ? t.toOwnerId : (t.fromOwnerId ?? t.toOwnerId);
  return effectiveOwnerId === userId;
}

export function LandownerDashboard() {
  const { user, wrappedKey } = useAuth();
  const [records, setRecords] = useState<LandRecordListItem[] | null>(null);
  const [transactions, setTransactions] = useState<MyTransaction[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [transferTarget, setTransferTarget] = useState<LandRecordListItem | null>(null);
  const [claimHeirOpen, setClaimHeirOpen] = useState(false);

  const [landRecordId, setLandRecordId] = useState("");
  const [type, setType] = useState<TransactionType>("REGISTRATION");
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
      const [recordList, myTransactions] = await Promise.all([listLandRecords(), getMyTransactions()]);
      if (!mountedRef.current) return;
      setRecords(recordList);
      setTransactions(myTransactions);
    } catch (err) {
      if (!mountedRef.current) return;
      setLoadError(getErrorMessage(err, "Failed to load your land records"));
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
        documentPath: upload.documentPath,
        documentHash: upload.documentHash,
      });
      setSigningOpen(true);
    } catch (err) {
      setFormError(getErrorMessage(err, "Failed to upload document"));
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
    setFile(null);
    setPendingInput(null);
    await loadData();
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="My Land"
        subtitle="Your registered land parcels and their transaction activity."
        action={
          <Button
            type="button"
            variant="secondary"
            icon={<HeartHandshake className="h-4 w-4" aria-hidden="true" />}
            onClick={() => setClaimHeirOpen(true)}
          >
            Claim as legal heir
          </Button>
        }
      />

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
        <LandRecordsTable records={records} currentUserId={user?.userId} onTransfer={setTransferTarget} />
      )}

      {records && records.length > 0 && (
        <Card>
          <h2 className="text-lg font-semibold text-slate-900">Create Transaction</h2>
          <p className="mt-1 text-sm text-slate-600">
            Registers or updates a land record you own. Sent for Village Officer review first. To transfer
            ownership, use the "Transfer ownership" button on the record itself, below.
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
                  onChange={(e) => setType(e.target.value as TransactionType)}
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
        <p className="mt-1 text-sm text-slate-600">
          Includes transfers where you're the buyer, even before you own the record yet.
        </p>
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
            {transactions.map((t) => {
              const direction =
                t.type === "TRANSFER"
                  ? t.isBuyer
                    ? `Buying from ${t.fromOwnerName}`
                    : `Selling to ${t.toOwnerName}`
                  : t.type === "SUCCESSION"
                    ? t.isBuyer
                      ? `Claiming from ${t.fromOwnerName} (deceased)`
                      : null
                    : null;
              const rowContent = (
                <>
                  <span>
                    <span className="font-medium text-slate-900">{t.type}</span>
                    <span className="ml-2 text-slate-500">Survey No. {t.surveyNumber}</span>
                    {direction && <span className="ml-2 text-slate-500">— {direction}</span>}
                  </span>
                  <TransactionStatusBadge status={t.status} />
                </>
              );
              const className =
                "flex items-center justify-between rounded-lg border border-slate-200 bg-white px-4 py-3 text-sm";
              return user && currentlyOwnedByUser(t, user.userId) ? (
                <Link key={t.id} to={`/land-records/${t.landRecordId}`} className={`${className} hover:bg-slate-50`}>
                  {rowContent}
                </Link>
              ) : (
                <div key={t.id} className={className}>
                  {rowContent}
                </div>
              );
            })}
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

      {transferTarget && (
        <TransferOwnershipModal
          landRecordId={transferTarget.id}
          surveyNumber={transferTarget.surveyNumber}
          onClose={() => setTransferTarget(null)}
          onTransferred={() => {
            setTransferTarget(null);
            setSuccessMessage("Transfer created and sent for Village Officer review.");
            loadData();
          }}
        />
      )}

      {claimHeirOpen && (
        <ClaimHeirModal
          onClose={() => setClaimHeirOpen(false)}
          onClaimed={() => {
            setClaimHeirOpen(false);
            setSuccessMessage("Succession claim submitted and sent for Village Officer review.");
            loadData();
          }}
        />
      )}
    </div>
  );
}
