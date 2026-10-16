import { useState, type FormEvent } from "react";
import axios from "axios";
import { Search } from "lucide-react";
import { verifyTransaction } from "../api/transactions";
import { Card } from "../components/Card";
import { ValidBadge } from "../components/ValidBadge";
import { ErrorState, LoadingState } from "../components/States";
import { PageHeader } from "../components/ui/PageHeader";
import { Button } from "../components/ui/Button";
import { Banner } from "../components/ui/Banner";
import { fieldInputClasses } from "../components/ui/Field";
import { ROLE_LABELS } from "../lib/roleHome";
import type { TransactionVerifyResult } from "../types";

function formatDateTime(iso: string) {
  return new Date(iso).toLocaleString();
}

function SectionHeading({ title, overallValid }: { title: string; overallValid: boolean }) {
  return (
    <div className="flex items-center justify-between">
      <h3 className="text-base font-semibold text-slate-900">{title}</h3>
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
      <PageHeader
        title="Verify"
        subtitle="A standalone diagnostic tool — independent of the approval workflow. Enter a transaction ID to independently re-check its signer identities, signature validity, and document integrity, regardless of the transaction's current status."
      />

      <Card>
        <form onSubmit={handleSubmit} className="flex flex-wrap items-end gap-3">
          <label className="flex min-w-64 flex-1 flex-col gap-1.5">
            <span className="text-sm font-medium text-slate-700">Transaction ID</span>
            <input
              type="text"
              required
              value={transactionId}
              onChange={(e) => setTransactionId(e.target.value)}
              placeholder="e.g. cm0abc123…"
              className={`${fieldInputClasses} font-mono`}
            />
          </label>
          <Button type="submit" loading={loading} icon={<Search className="h-4 w-4" aria-hidden="true" />}>
            {loading ? "Verifying…" : "Verify"}
          </Button>
        </form>
      </Card>

      {loading && <LoadingState label="Running independent verification…" />}
      {error && <ErrorState label={error} />}

      {result && (
        <div className="flex flex-col gap-4">
          <Card>
            <SectionHeading title="Signer Identity" overallValid={allIdentitiesValid} />
            <p className="mt-1 text-xs text-slate-500">
              Each signer's certificate re-verified live against the CA's public key.
            </p>
            <ul className="mt-3 flex flex-col gap-2">
              {result.signerIdentity.map((s, i) => (
                <li key={i} className="flex items-center justify-between rounded-lg bg-slate-50 px-3 py-2 text-sm">
                  <span>
                    {s.actorName}{" "}
                    <span className="text-xs uppercase tracking-wide text-slate-500">
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
            <p className="mt-1 text-xs text-slate-500">
              Each signature's payload rebuilt and re-verified against the actor's public key.
            </p>
            <ul className="mt-3 flex flex-col gap-2">
              {result.signatureValidity.map((s, i) => (
                <li key={i} className="flex items-center justify-between rounded-lg bg-slate-50 px-3 py-2 text-sm">
                  <span>
                    {s.actorName}{" "}
                    <span className="text-xs uppercase tracking-wide text-slate-500">
                      {ROLE_LABELS[s.role] ?? s.role}
                    </span>
                    <span className="ml-2 text-xs text-slate-500">{formatDateTime(s.signedAt)}</span>
                  </span>
                  <ValidBadge valid={s.valid} />
                </li>
              ))}
            </ul>
          </Card>

          <Card>
            <SectionHeading title="Document Integrity" overallValid={result.documentIntegrity.match} />
            <p className="mt-1 text-xs text-slate-500">
              The stored document is re-read from disk and its SHA-256 hash recomputed on the spot.
            </p>
            <div className="mt-3">
              {result.documentIntegrity.match ? (
                <Banner variant="success">The document on disk matches the hash recorded at transaction creation.</Banner>
              ) : (
                <Banner variant="danger">
                  {result.documentIntegrity.error ?? "The document hash does not match what was recorded."}
                </Banner>
              )}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
