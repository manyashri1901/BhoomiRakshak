import { useEffect, useState } from "react";
import axios from "axios";
import { verifyTransaction, type ReviewResult, isAutoReject } from "../api/transactions";
import { downloadDocument } from "../api/documents";
import { Card } from "./Card";
import { ValidBadge } from "./ValidBadge";
import { EmptyState, ErrorState, LoadingState } from "./States";
import { ROLE_LABELS } from "../lib/roleHome";
import type { TransactionVerifyResult, TransactionWithChain } from "../types";

interface ReviewQueueProps {
  title: string;
  description: string;
  transactions: TransactionWithChain[] | null;
  loadError: string | null;
  emptyLabel: string;
  onApprove: (id: string) => Promise<ReviewResult>;
  onReject: (id: string, reason: string) => Promise<ReviewResult>;
  onDecided: () => void;
}

function formatDateTime(iso: string) {
  return new Date(iso).toLocaleString();
}

export function ReviewQueue({
  title,
  description,
  transactions,
  loadError,
  emptyLabel,
  onApprove,
  onReject,
  onDecided,
}: ReviewQueueProps) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [liveCheck, setLiveCheck] = useState<TransactionVerifyResult | null>(null);
  const [checking, setChecking] = useState(false);
  const [rejecting, setRejecting] = useState(false);
  const [reason, setReason] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const selected = transactions?.find((t) => t.id === selectedId) ?? null;

  useEffect(() => {
    if (!selectedId) {
      setLiveCheck(null);
      return;
    }
    let cancelled = false;
    setChecking(true);
    setLiveCheck(null);
    verifyTransaction(selectedId)
      .then((result) => {
        if (!cancelled) setLiveCheck(result);
      })
      .finally(() => {
        if (!cancelled) setChecking(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedId]);

  function select(id: string) {
    setSelectedId(id);
    setRejecting(false);
    setReason("");
    setActionError(null);
    setActionMessage(null);
  }

  async function handleApprove() {
    if (!selectedId) return;
    setBusy(true);
    setActionError(null);
    try {
      const result = await onApprove(selectedId);
      if (isAutoReject(result)) {
        setActionMessage(`Auto-rejected: ${result.reason}`);
      } else {
        setActionMessage("Approved and signed.");
      }
      setSelectedId(null);
      onDecided();
    } catch (err) {
      setActionError(
        axios.isAxiosError(err) ? (err.response?.data?.error ?? "Review failed") : "Review failed",
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleReject() {
    if (!selectedId) return;
    if (!reason.trim()) {
      setActionError("A reason is required to reject.");
      return;
    }
    setBusy(true);
    setActionError(null);
    try {
      await onReject(selectedId, reason.trim());
      setActionMessage("Rejected.");
      setSelectedId(null);
      onDecided();
    } catch (err) {
      setActionError(
        axios.isAxiosError(err) ? (err.response?.data?.error ?? "Review failed") : "Review failed",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h2 className="font-serif text-lg font-semibold text-ink">{title}</h2>
        <p className="mt-1 text-sm text-muted">{description}</p>
      </div>

      {loadError && <ErrorState label={loadError} />}
      {!loadError && transactions === null && <LoadingState label="Loading queue…" />}
      {!loadError && transactions !== null && transactions.length === 0 && (
        <EmptyState label={emptyLabel} />
      )}

      {actionMessage && (
        <p className="rounded-md bg-valid-chip px-3 py-2 text-sm text-dark-cocoa">{actionMessage}</p>
      )}

      {transactions !== null && transactions.length > 0 && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)]">
          <div className="flex flex-col gap-2">
            {transactions.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => select(t.id)}
                className={`rounded-md border px-4 py-3 text-left text-sm transition-colors ${
                  t.id === selectedId
                    ? "border-camel bg-neutral-chip"
                    : "border-border-subtle bg-surface hover:bg-neutral-chip"
                }`}
              >
                <div className="font-medium text-ink">{t.type}</div>
                <div className="text-xs text-muted">
                  Survey No. {t.landRecord.surveyNumber} — {t.landRecord.location}
                </div>
                <div className="mt-1 text-xs text-muted">{formatDateTime(t.createdAt)}</div>
              </button>
            ))}
          </div>

          <div>
            {!selected && <EmptyState label="Select a transaction to review." />}

            {selected && (
              <Card>
                <div>
                  <h3 className="font-serif text-base font-semibold text-ink">
                    {selected.type} — Survey No. {selected.landRecord.surveyNumber}
                  </h3>
                  <p className="text-sm text-muted">{selected.landRecord.location}</p>
                </div>

                <button
                  type="button"
                  onClick={() => downloadDocument(selected.documentPath)}
                  className="mt-3 inline-flex items-center gap-1.5 rounded-md border border-border-subtle px-3 py-1.5 text-sm font-medium text-ink underline hover:bg-neutral-chip"
                >
                  Download document
                </button>

                <div className="mt-4">
                  <h4 className="text-xs font-medium uppercase tracking-wide text-muted">
                    Prior signatures (live-verified)
                  </h4>
                  {checking && <p className="mt-2 text-sm text-muted">Verifying…</p>}
                  {!checking && liveCheck && (
                    <ul className="mt-2 flex flex-col gap-2">
                      {liveCheck.signatureValidity.map((s, i) => (
                        <li
                          key={i}
                          className="flex items-center justify-between rounded-md bg-neutral-chip px-3 py-2 text-sm"
                        >
                          <span>
                            {s.actorName}{" "}
                            <span className="text-xs uppercase tracking-wide text-muted">
                              {ROLE_LABELS[s.role] ?? s.role}
                            </span>
                          </span>
                          <ValidBadge valid={s.valid} />
                        </li>
                      ))}
                    </ul>
                  )}
                  {!checking && liveCheck && !liveCheck.documentIntegrity.match && (
                    <p className="mt-2 rounded-md bg-danger-chip px-3 py-2 text-sm text-wax-seal">
                      Document integrity check failed — the file on disk no longer matches the
                      recorded hash.
                    </p>
                  )}
                </div>

                <div className="mt-5 flex flex-col gap-3 border-t border-border-subtle pt-4">
                  {actionError && <ErrorState label={actionError} />}

                  {!rejecting ? (
                    <div className="flex gap-3">
                      <button
                        type="button"
                        onClick={handleApprove}
                        disabled={busy}
                        className="rounded-md bg-coffee px-4 py-2 text-sm font-semibold text-apricot hover:bg-coffee-hover disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        {busy ? "Working…" : "Approve"}
                      </button>
                      <button
                        type="button"
                        onClick={() => setRejecting(true)}
                        disabled={busy}
                        className="rounded-md border border-wax-seal px-4 py-2 text-sm font-semibold text-wax-seal hover:bg-danger-chip disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        Reject
                      </button>
                    </div>
                  ) : (
                    <div className="flex flex-col gap-2">
                      <label className="flex flex-col gap-1">
                        <span className="text-sm font-medium text-ink">Reason for rejection</span>
                        <textarea
                          value={reason}
                          onChange={(e) => setReason(e.target.value)}
                          rows={3}
                          className="rounded-md border border-border-subtle px-3 py-2 text-sm outline-none focus:border-camel focus:ring-1 focus:ring-camel"
                        />
                      </label>
                      <div className="flex gap-3">
                        <button
                          type="button"
                          onClick={handleReject}
                          disabled={busy}
                          className="rounded-md bg-wax-seal px-4 py-2 text-sm font-semibold text-apricot hover:bg-wax-seal-hover disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          {busy ? "Working…" : "Confirm Reject"}
                        </button>
                        <button
                          type="button"
                          onClick={() => setRejecting(false)}
                          disabled={busy}
                          className="rounded-md border border-border-subtle px-4 py-2 text-sm font-medium text-ink hover:bg-neutral-chip"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </Card>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
