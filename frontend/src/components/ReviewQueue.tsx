import { useEffect, useState } from "react";
import axios from "axios";
import { Download } from "lucide-react";
import { verifyTransaction, isAutoReject, type ReviewResult, type PreparedSignature } from "../api/transactions";
import { downloadDocument } from "../api/documents";
import { signAndSubmit } from "../lib/signAndSubmit";
import { useAuth } from "../context/AuthContext";
import { Card } from "./Card";
import { Button } from "./ui/Button";
import { Banner } from "./ui/Banner";
import { Field, fieldInputClasses } from "./ui/Field";
import { SecurityDetailsCard } from "./ui/SecurityDetailsCard";
import { PasswordPrompt } from "./PasswordPrompt";
import { EmptyState, ErrorState, LoadingState } from "./States";
import { TransactionStatusBadge } from "./StatusBadge";
import { ROLE_LABELS } from "../lib/roleHome";
import type { TransactionVerifyResult, TransactionWithChain } from "../types";

interface ReviewQueueProps {
  title: string;
  description: string;
  transactions: TransactionWithChain[] | null;
  loadError: string | null;
  emptyLabel: string;
  prepareApprove: (id: string) => Promise<PreparedSignature>;
  submitApprove: (id: string, nonce: string, signatureValue: string) => Promise<ReviewResult>;
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
  prepareApprove,
  submitApprove,
  onReject,
  onDecided,
}: ReviewQueueProps) {
  const { wrappedKey } = useAuth();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [liveCheck, setLiveCheck] = useState<TransactionVerifyResult | null>(null);
  const [checking, setChecking] = useState(false);
  const [rejecting, setRejecting] = useState(false);
  const [signingOpen, setSigningOpen] = useState(false);
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

  function handleResult(result: ReviewResult) {
    if (isAutoReject(result)) {
      setActionMessage(`Auto-rejected: ${result.reason}`);
    } else {
      setActionMessage("Approved and signed.");
    }
    setSelectedId(null);
    onDecided();
  }

  async function handleApproveWithPassword(password: string) {
    if (!selectedId) return;
    if (!wrappedKey) {
      throw new Error("No signing key on this account — log out and back in, or re-register.");
    }
    const result = await signAndSubmit(
      wrappedKey,
      password,
      () => prepareApprove(selectedId),
      (nonce, signatureValue) => submitApprove(selectedId, nonce, signatureValue),
    );
    setSigningOpen(false);
    handleResult(result);
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
      const result = await onReject(selectedId, reason.trim());
      handleResult(result);
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
        <h2 className="text-lg font-semibold text-slate-900">{title}</h2>
        <p className="mt-1 text-sm text-slate-600">{description}</p>
      </div>

      {loadError && <ErrorState label={loadError} />}
      {!loadError && transactions === null && <LoadingState label="Loading queue…" />}
      {!loadError && transactions !== null && transactions.length === 0 && (
        <EmptyState label={emptyLabel} />
      )}

      {actionMessage && <Banner variant="success">{actionMessage}</Banner>}

      {transactions !== null && transactions.length > 0 && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)]">
          <div className="flex flex-col gap-2">
            {transactions.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => select(t.id)}
                className={`rounded-lg border px-4 py-3 text-left text-sm transition-colors ${
                  t.id === selectedId
                    ? "border-teal bg-teal/5"
                    : "border-slate-200 bg-white hover:bg-slate-50"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium text-slate-900">{t.type}</span>
                  <TransactionStatusBadge status={t.status} />
                </div>
                <div className="text-xs text-slate-500">
                  Survey No. {t.landRecord.surveyNumber} — {t.landRecord.location}
                </div>
                <div className="mt-1 text-xs text-slate-400">{formatDateTime(t.createdAt)}</div>
              </button>
            ))}
          </div>

          <div>
            {!selected && <EmptyState label="Select a transaction to review." />}

            {selected && (
              <div className="flex flex-col gap-4">
                <Card>
                  <div>
                    <h3 className="text-base font-semibold text-slate-900">
                      {selected.type} — Survey No. {selected.landRecord.surveyNumber}
                    </h3>
                    <p className="text-sm text-slate-600">{selected.landRecord.location}</p>
                  </div>

                  <button
                    type="button"
                    onClick={() => downloadDocument(selected.documentPath)}
                    className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50"
                  >
                    <Download className="h-4 w-4" aria-hidden="true" />
                    Download document
                  </button>

                  {!checking && liveCheck && !liveCheck.documentIntegrity.match && (
                    <div className="mt-4">
                      <Banner variant="danger">
                        Document integrity check failed — the file on disk no longer matches the
                        recorded hash.
                      </Banner>
                    </div>
                  )}

                  <div className="mt-5 flex flex-col gap-3 border-t border-slate-200 pt-4">
                    {actionError && <ErrorState label={actionError} />}

                    {!rejecting ? (
                      <div className="flex gap-3">
                        <Button onClick={() => setSigningOpen(true)} disabled={busy}>
                          Approve
                        </Button>
                        <Button variant="danger" onClick={() => setRejecting(true)} disabled={busy}>
                          Reject
                        </Button>
                      </div>
                    ) : (
                      <div className="flex flex-col gap-2">
                        <Field label="Reason for rejection">
                          <textarea
                            value={reason}
                            onChange={(e) => setReason(e.target.value)}
                            rows={3}
                            className={fieldInputClasses}
                          />
                        </Field>
                        <div className="flex gap-3">
                          <Button variant="danger" onClick={handleReject} loading={busy}>
                            {busy ? "Working…" : "Confirm Reject"}
                          </Button>
                          <Button variant="secondary" onClick={() => setRejecting(false)} disabled={busy}>
                            Cancel
                          </Button>
                        </div>
                      </div>
                    )}
                  </div>
                </Card>

                {checking && <LoadingState label="Verifying signatures…" />}
                {!checking && (
                  <SecurityDetailsCard
                    documentHash={selected.documentHash}
                    signers={selected.signatures.map((sig, i) => ({
                      name: sig.actor.name,
                      roleLabel: ROLE_LABELS[sig.role] ?? sig.role,
                      fingerprint: sig.actor.certificate?.fingerprint ?? null,
                      valid: liveCheck?.signatureValidity[i]?.valid ?? sig.valid,
                    }))}
                  />
                )}
              </div>
            )}
          </div>
        </div>
      )}

      <PasswordPrompt
        open={signingOpen}
        title="Sign approval"
        description="Enter your password to unlock your signing key and approve this transaction."
        confirmLabel="Approve & Sign"
        onConfirm={handleApproveWithPassword}
        onCancel={() => setSigningOpen(false)}
      />
    </div>
  );
}
