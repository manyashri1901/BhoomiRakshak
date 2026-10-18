import { useCallback, useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { AlertTriangle, ArrowRightLeft, FlaskConical } from "lucide-react";
import { getLandRecordHistory } from "../api/landRecords";
import { tamperTransaction } from "../api/dev";
import { formatAreaWithConversion } from "../lib/areaUnits";
import { getErrorMessage } from "../lib/errorMessage";
import { Card } from "../components/Card";
import { LandRecordStatusBadge, TransactionStatusBadge } from "../components/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { Button } from "../components/ui/Button";
import { Banner } from "../components/ui/Banner";
import { SecurityDetailsCard } from "../components/ui/SecurityDetailsCard";
import { TransferOwnershipModal } from "../components/TransferOwnershipModal";
import { useAuth } from "../context/AuthContext";
import { ROLE_LABELS } from "../lib/roleHome";
import type { HistoryTransaction, LandRecordHistory } from "../types";

function formatDateTime(iso: string) {
  return new Date(iso).toLocaleString();
}

interface OwnershipSpan {
  ownerName: string;
  since: string;
  transactionId: string | null;
  // null = the record's initial owner (no transaction moved it to them).
  viaType: "TRANSFER" | "SUCCESSION" | null;
}

// Derived, not a separate table: only an APPROVED TRANSFER or SUCCESSION
// ever actually moves ownership (REGISTRATION/UPDATE always have
// toOwnerId === the caller themselves, per routes/transactions.ts) — so
// the ownership history is exactly the record's current owner as of
// creation, followed by one span per approved ownership-changing
// transaction in order. "since" uses the Registrar's own signing time
// (the moment ownership legally moved), not the transaction's
// creation/submission date.
function buildOwnershipHistory(landRecord: LandRecordHistory["landRecord"], transactions: HistoryTransaction[]): OwnershipSpan[] {
  const approvedMoves = transactions.filter(
    (t) => (t.type === "TRANSFER" || t.type === "SUCCESSION") && t.status === "APPROVED",
  );

  function registrarSignedAt(t: HistoryTransaction): string {
    return t.signatures.find((s) => s.role === "REGISTRAR")?.signedAt ?? t.createdAt;
  }

  if (approvedMoves.length === 0) {
    return [{ ownerName: landRecord.currentOwnerName ?? "Unknown", since: landRecord.createdAt, transactionId: null, viaType: null }];
  }

  const spans: OwnershipSpan[] = [
    {
      ownerName: approvedMoves[0].fromOwnerName ?? "Unknown",
      since: landRecord.createdAt,
      transactionId: null,
      viaType: null,
    },
  ];
  for (const t of approvedMoves) {
    spans.push({ ownerName: t.toOwnerName, since: registrarSignedAt(t), transactionId: t.id, viaType: t.type as "TRANSFER" | "SUCCESSION" });
  }
  return spans;
}

function ownershipSpanReason(span: OwnershipSpan): string | null {
  return span.viaType === "SUCCESSION" ? "Succession (owner deceased)" : null;
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
      setTamperError(getErrorMessage(err, "Tamper failed"));
    } finally {
      setTampering(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="font-medium text-slate-900">{transaction.type}</span>
            <TransactionStatusBadge status={transaction.status} />
          </div>
          <span className="text-xs text-slate-500">{formatDateTime(transaction.createdAt)}</span>
        </div>

        {transaction.rejectReason && (
          <div className="mt-2">
            <Banner variant="danger">Rejected: {transaction.rejectReason}</Banner>
          </div>
        )}

        {isTampered && (
          <div className="mt-3">
            <Banner variant="danger">
              <span className="font-semibold">Tamper detected.</span>{" "}
              {documentMismatch
                ? "Document hash no longer matches stored signature — this record has been tampered with after approval."
                : "A signature in this transaction's chain no longer verifies against the stored data."}
            </Banner>
          </div>
        )}

        {canTamper && transaction.status === "APPROVED" && (
          <div className="mt-4 border-t border-slate-200 pt-3">
            {tamperError && (
              <div className="mb-2">
                <ErrorState label={tamperError} />
              </div>
            )}
            <Button
              variant="danger"
              onClick={handleTamper}
              loading={tampering}
              icon={<FlaskConical className="h-4 w-4" aria-hidden="true" />}
            >
              {tampering ? "Tampering…" : "Simulate tampering (test mode)"}
            </Button>
            <p className="mt-1.5 flex items-start gap-1.5 text-xs text-slate-500">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              Test mode only — directly overwrites the stored document hash in the database, bypassing
              the signing flow entirely, to prove verification catches it.
            </p>
          </div>
        )}
      </Card>

      <SecurityDetailsCard
        documentHash={transaction.documentHash}
        signers={transaction.signatures.map((sig) => ({
          name: sig.actorName,
          roleLabel: ROLE_LABELS[sig.role] ?? sig.role,
          valid: sig.valid,
        }))}
      />
    </div>
  );
}

export function LandRecordDetail() {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const [data, setData] = useState<LandRecordHistory | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [transferOpen, setTransferOpen] = useState(false);
  const [transferMessage, setTransferMessage] = useState<string | null>(null);

  const load = useCallback(() => {
    if (!id) return;
    getLandRecordHistory(id)
      .then(setData)
      .catch((err) => {
        setError(getErrorMessage(err, "Failed to load land record"));
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
  const canTransfer = user?.role === "LANDOWNER" && landRecord.currentOwnerId === user.userId && landRecord.status === "ACTIVE";
  const ownershipHistory = buildOwnershipHistory(landRecord, transactions);
  const currentSpan = ownershipHistory[ownershipHistory.length - 1];
  const previousSpan = ownershipHistory.length > 1 ? ownershipHistory[ownershipHistory.length - 2] : null;
  const previousOwnerDeceased = currentSpan?.viaType === "SUCCESSION" ? previousSpan : null;

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold text-slate-900">Survey No. {landRecord.surveyNumber}</h1>
            <p className="mt-1 text-sm text-slate-600">{landRecord.location}</p>
          </div>
          <div className="flex items-center gap-3">
            <LandRecordStatusBadge status={landRecord.status} />
            {previousOwnerDeceased && (
              <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600">
                Previous owner: {previousOwnerDeceased.ownerName} (deceased)
              </span>
            )}
            {canTransfer && (
              <Button
                type="button"
                icon={<ArrowRightLeft className="h-4 w-4" aria-hidden="true" />}
                onClick={() => setTransferOpen(true)}
              >
                Transfer ownership
              </Button>
            )}
          </div>
        </div>
        <dl className="mt-4 grid grid-cols-2 gap-4 text-sm sm:grid-cols-3">
          <div>
            <dt className="text-slate-500">Area</dt>
            <dd className="text-slate-900">{formatAreaWithConversion(landRecord.area, landRecord.areaUnit)}</dd>
          </div>
          <div>
            <dt className="text-slate-500">Registered</dt>
            <dd className="text-slate-900">{formatDateTime(landRecord.createdAt)}</dd>
          </div>
          <div>
            <dt className="text-slate-500">Current owner</dt>
            <dd className="text-slate-900">{landRecord.currentOwnerName ?? "—"}</dd>
          </div>
        </dl>
        {transferMessage && (
          <div className="mt-4">
            <Banner variant="success">{transferMessage}</Banner>
          </div>
        )}
      </Card>

      <Card>
        <h2 className="text-lg font-semibold text-slate-900">Ownership history</h2>
        <p className="mt-1 text-sm text-slate-600">Who has owned this record, and when it changed hands.</p>
        <ol className="mt-4 flex flex-col gap-3">
          {ownershipHistory.map((span, index) => {
            const reason = ownershipSpanReason(span);
            return (
              <li key={span.transactionId ?? "origin"} className="flex items-start gap-3 text-sm">
                <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-teal" aria-hidden="true" />
                <span>
                  <span className="font-medium text-slate-900">{span.ownerName}</span>
                  <span className="ml-2 text-slate-500">since {formatDateTime(span.since)}</span>
                  {reason && (
                    <span className="ml-2 rounded-full bg-amber-50 px-2 py-0.5 text-xs font-medium text-amber-700">
                      {reason}
                    </span>
                  )}
                  {index === ownershipHistory.length - 1 && (
                    <span className="ml-2 rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-600">Current</span>
                  )}
                </span>
              </li>
            );
          })}
        </ol>
      </Card>

      <div>
        <h2 className="text-lg font-semibold text-slate-900">Transaction history</h2>
        <p className="mt-1 text-sm text-slate-600">
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

      {transferOpen && (
        <TransferOwnershipModal
          landRecordId={landRecord.id}
          surveyNumber={landRecord.surveyNumber}
          onClose={() => setTransferOpen(false)}
          onTransferred={() => {
            setTransferOpen(false);
            setTransferMessage("Transfer created and sent for Village Officer review.");
            load();
          }}
        />
      )}
    </div>
  );
}
