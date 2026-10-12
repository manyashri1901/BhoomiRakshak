import { useCallback, useEffect, useState, type FormEvent } from "react";
import axios from "axios";
import { getCRL, getCertificateByUserId, revokeCertificate } from "../api/certificates";
import {
  verifyAuditChain,
  getAuditEntryCount,
  getAuditHead,
  type AuditVerificationResult,
  type AuditChainHead,
} from "../api/audit";
import { Card } from "../components/Card";
import { ErrorState, LoadingState, EmptyState } from "../components/States";
import { UserPicker } from "../components/UserPicker";
import { ROLE_LABELS } from "../lib/roleHome";
import type { RevokedCertificateSummary, UserSummary } from "../types";

// ADMIN-only: revoke a user's certificate and view the Certificate
// Revocation List (CRL). This is the only place in the UI that writes a
// revocation — every other verify path (certificates lookup, transaction
// /verify, land-record history) only ever reads revoked/expired state live
// via lib/ca.ts's verifyCertificate(), never a cached flag.
export function AdminDashboard() {
  const [crl, setCrl] = useState<RevokedCertificateSummary[] | null>(null);
  const [crlError, setCrlError] = useState<string | null>(null);

  const [targetUser, setTargetUser] = useState<UserSummary | null>(null);
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const [auditResult, setAuditResult] = useState<AuditVerificationResult | null>(null);
  const [auditEntryCount, setAuditEntryCount] = useState<number | null>(null);
  const [auditHead, setAuditHead] = useState<AuditChainHead | null>(null);
  const [auditChecking, setAuditChecking] = useState(false);
  const [auditError, setAuditError] = useState<string | null>(null);

  const loadCrl = useCallback(() => {
    getCRL()
      .then(setCrl)
      .catch((err) => {
        setCrlError(
          axios.isAxiosError(err) ? (err.response?.data?.error ?? "Failed to load CRL") : "Failed to load CRL",
        );
      });
  }, []);

  useEffect(() => {
    loadCrl();
  }, [loadCrl]);

  async function handleVerifyIntegrity() {
    setAuditChecking(true);
    setAuditError(null);
    try {
      const [result, count, head] = await Promise.all([
        verifyAuditChain(),
        getAuditEntryCount(),
        getAuditHead(),
      ]);
      setAuditResult(result);
      setAuditEntryCount(count);
      setAuditHead(head);
    } catch (err) {
      setAuditError(
        axios.isAxiosError(err)
          ? (err.response?.data?.error ?? "Failed to verify audit chain")
          : "Failed to verify audit chain",
      );
    } finally {
      setAuditChecking(false);
    }
  }

  async function handleRevoke(event: FormEvent) {
    event.preventDefault();
    setFormError(null);
    setSuccessMessage(null);

    if (!targetUser) {
      setFormError("Select the user whose certificate you want to revoke.");
      return;
    }
    if (!reason.trim()) {
      setFormError("A reason is required to revoke a certificate.");
      return;
    }

    setSubmitting(true);
    try {
      const certificate = await getCertificateByUserId(targetUser.id);
      if (certificate.revoked) {
        setFormError(`${targetUser.name}'s certificate is already revoked.`);
        return;
      }
      await revokeCertificate(certificate.id, reason.trim());
      setSuccessMessage(`Revoked ${targetUser.name}'s certificate.`);
      setTargetUser(null);
      setReason("");
      loadCrl();
    } catch (err) {
      setFormError(
        axios.isAxiosError(err) ? (err.response?.data?.error ?? "Revocation failed") : "Revocation failed",
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="font-serif text-2xl font-semibold text-ink">Admin — Certificate Authority</h1>
        <p className="mt-1 text-sm text-muted">
          Revoke a compromised or retired certificate, and review the Certificate Revocation List (CRL).
          Revoking takes effect immediately across every signing and verification path.
        </p>
      </div>

      <Card>
        <h2 className="font-serif text-lg font-semibold text-ink">Revoke a certificate</h2>
        <form onSubmit={handleRevoke} className="mt-4 flex flex-col gap-4">
          <label className="flex flex-col gap-1">
            <span className="text-sm font-medium text-ink">User</span>
            <UserPicker selected={targetUser} onSelect={setTargetUser} placeholder="Search by name…" />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-sm font-medium text-ink">Reason</span>
            <input
              type="text"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. Private key compromised"
              className="rounded-md border border-border-subtle px-3 py-2 text-sm outline-none focus:border-camel focus:ring-1 focus:ring-camel"
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
            {submitting ? "Revoking…" : "Revoke Certificate"}
          </button>
        </form>
      </Card>

      <Card>
        <h2 className="font-serif text-lg font-semibold text-ink">Certificate Revocation List (CRL)</h2>
        <p className="mt-1 text-sm text-muted">Every certificate revoked so far, most recent first.</p>

        <div className="mt-4">
          {crlError && <ErrorState label={crlError} />}
          {!crlError && crl === null && <LoadingState />}
          {!crlError && crl !== null && crl.length === 0 && (
            <EmptyState label="No certificates have been revoked." />
          )}
          {!crlError && crl !== null && crl.length > 0 && (
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-border-subtle text-xs uppercase tracking-wide text-muted">
                  <th className="pb-2 pr-4">Subject</th>
                  <th className="pb-2 pr-4">Role</th>
                  <th className="pb-2 pr-4">Fingerprint</th>
                  <th className="pb-2 pr-4">Revoked at</th>
                  <th className="pb-2">Reason</th>
                </tr>
              </thead>
              <tbody>
                {crl.map((entry) => (
                  <tr key={entry.certificateId} className="border-b border-border-subtle last:border-0">
                    <td className="py-2 pr-4 text-ink">{entry.subjectName}</td>
                    <td className="py-2 pr-4 text-muted">{ROLE_LABELS[entry.role]}</td>
                    <td className="py-2 pr-4 font-mono text-xs text-muted">{entry.fingerprint.slice(0, 16)}…</td>
                    <td className="py-2 pr-4 text-muted">{new Date(entry.revokedAt).toLocaleString()}</td>
                    <td className="py-2 text-muted">{entry.revokedReason ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </Card>

      <Card>
        <h2 className="font-serif text-lg font-semibold text-ink">Verify audit chain integrity</h2>
        <p className="mt-1 text-sm text-muted">
          Recomputes every audit log entry's hash and checks its link to the previous entry — a
          tamper anywhere in the chain (edited or deleted row) is reported as the first broken
          sequence number, not just "something's wrong."
        </p>

        <button
          type="button"
          onClick={handleVerifyIntegrity}
          disabled={auditChecking}
          className="mt-4 self-start rounded-md bg-coffee px-4 py-2 text-sm font-semibold text-apricot hover:bg-coffee-hover disabled:cursor-not-allowed disabled:opacity-60"
        >
          {auditChecking ? "Verifying…" : "Verify integrity"}
        </button>

        {auditError && <ErrorState label={auditError} />}

        {auditResult && (
          <div className="mt-4 flex flex-col gap-2 text-sm">
            <p className={auditResult.valid ? "text-dark-cocoa" : "text-wax-seal"}>
              <span className="font-semibold">{auditResult.valid ? "Chain intact." : "Chain broken."}</span>{" "}
              {auditResult.valid
                ? `All ${auditResult.checked} entries verified.`
                : `${auditResult.checked} entries verified before the break at seq ${auditResult.firstBrokenSeq}: ${auditResult.reason}`}
            </p>
            {auditEntryCount !== null && (
              <p className="text-muted">Total entries in the log: {auditEntryCount}</p>
            )}
            {auditHead?.hash && (
              <p className="break-all text-muted">
                Head: seq {auditHead.seq} —{" "}
                <span className="font-mono text-xs">{auditHead.hash}</span>
              </p>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}
