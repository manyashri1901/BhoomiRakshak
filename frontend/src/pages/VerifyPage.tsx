import { useState, type FormEvent } from "react";
import axios from "axios";
import { verifyTransaction } from "../api/transactions";
import { Card } from "../components/Card";
import { ValidBadge } from "../components/ValidBadge";
import { ErrorState, LoadingState } from "../components/States";
import { ROLE_LABELS } from "../lib/roleHome";
import type { TransactionVerifyResult } from "../types";

function formatDateTime(iso: string) {
  return new Date(iso).toLocaleString();
}

function SectionHeading({ title, overallValid }: { title: string; overallValid: boolean }) {
  return (
    <div className="flex items-center justify-between">
      <h3 className="font-serif text-base font-semibold text-ink">{title}</h3>
      <ValidBadge valid={overallValid} label={overallValid ? "Pass" : "Fail"} />
    </div>
  );
}

export function VerifyPage() {
  const [transactionId, setTransactionId] = useState("");
  const [result, setResult] = useState<TransactionVerifyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      const data = await verifyTransaction(transactionId.trim());
      setResult(data);
    } catch (err) {
      setError(
        axios.isAxiosError(err)
          ? (err.response?.data?.error ?? "Verification failed")
          : "Could not reach the server. Please try again.",
      );
    } finally {
      setLoading(false);
    }
  }

  const allIdentitiesValid = result?.signerIdentity.every((s) => s.certificateValid) ?? false;
  const allSignaturesValid = result?.signatureValidity.every((s) => s.valid) ?? false;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="font-serif text-2xl font-semibold text-ink">Verify</h1>
        <p className="mt-1 max-w-2xl text-sm text-muted">
          A standalone diagnostic tool — independent of the approval workflow. Enter a transaction
          ID to independently re-check its signer identities, signature validity, and document
          integrity, regardless of the transaction's current status.
        </p>
      </div>

      <Card>
        <form onSubmit={handleSubmit} className="flex flex-wrap items-end gap-3">
          <label className="flex flex-1 min-w-64 flex-col gap-1">
            <span className="text-sm font-medium text-ink">Transaction ID</span>
            <input
              type="text"
              required
              value={transactionId}
              onChange={(e) => setTransactionId(e.target.value)}
              placeholder="e.g. cm0abc123…"
              className="rounded-md border border-border-subtle px-3 py-2 font-mono text-sm outline-none focus:border-camel focus:ring-1 focus:ring-camel"
            />
          </label>
          <button
            type="submit"
            disabled={loading}
            className="rounded-md bg-coffee px-4 py-2 text-sm font-semibold text-apricot hover:bg-coffee-hover disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? "Verifying…" : "Verify"}
          </button>
        </form>
      </Card>

      {loading && <LoadingState label="Running independent verification…" />}
      {error && <ErrorState label={error} />}

      {result && (
        <div className="flex flex-col gap-4">
          <Card>
            <SectionHeading title="Signer Identity" overallValid={allIdentitiesValid} />
            <p className="mt-1 text-xs text-muted">
              Each signer's certificate re-verified live against the CA's public key.
            </p>
            <ul className="mt-3 flex flex-col gap-2">
              {result.signerIdentity.map((s, i) => (
                <li key={i} className="flex items-center justify-between rounded-md bg-neutral-chip px-3 py-2 text-sm">
                  <span>
                    {s.actorName}{" "}
                    <span className="text-xs uppercase tracking-wide text-muted">
                      {ROLE_LABELS[s.role] ?? s.role}
                    </span>
                  </span>
                  <ValidBadge valid={s.certificateValid} label={s.certificateValid ? "Certificate Valid" : "Certificate Invalid"} />
                </li>
              ))}
            </ul>
          </Card>

          <Card>
            <SectionHeading title="Signature Validity" overallValid={allSignaturesValid} />
            <p className="mt-1 text-xs text-muted">
              Each signature's payload rebuilt and re-verified against the actor's public key.
            </p>
            <ul className="mt-3 flex flex-col gap-2">
              {result.signatureValidity.map((s, i) => (
                <li key={i} className="flex items-center justify-between rounded-md bg-neutral-chip px-3 py-2 text-sm">
                  <span>
                    {s.actorName}{" "}
                    <span className="text-xs uppercase tracking-wide text-muted">
                      {ROLE_LABELS[s.role] ?? s.role}
                    </span>
                    <span className="ml-2 text-xs text-muted">{formatDateTime(s.signedAt)}</span>
                  </span>
                  <ValidBadge valid={s.valid} />
                </li>
              ))}
            </ul>
          </Card>

          <Card>
            <SectionHeading title="Document Integrity" overallValid={result.documentIntegrity.match} />
            <p className="mt-1 text-xs text-muted">
              The stored document is re-read from disk and its SHA-256 hash recomputed on the spot.
            </p>
            <div className="mt-3 rounded-md bg-neutral-chip px-3 py-2 text-sm">
              {result.documentIntegrity.match
                ? "The document on disk matches the hash recorded at transaction creation."
                : (result.documentIntegrity.error ?? "The document hash does not match what was recorded.")}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
