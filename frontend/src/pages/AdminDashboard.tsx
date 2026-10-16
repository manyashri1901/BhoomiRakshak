import { useCallback, useEffect, useState, type FormEvent } from "react";
import axios from "axios";
import { CheckCircle2, ShieldCheck, XCircle } from "lucide-react";
import { getCRL, getCertificateByUserId, revokeCertificate } from "../api/certificates";
import {
  verifyAuditChain,
  getAuditEntryCount,
  getAuditHead,
  type AuditVerificationResult,
  type AuditChainHead,
} from "../api/audit";
import {
  getAnchors,
  verifyAnchors as verifyAnchorsApi,
  anchorNow,
  type AnchorSummary,
  type AnchorVerificationResult,
} from "../api/anchor";
import { Card } from "../components/Card";
import { ValidBadge } from "../components/ValidBadge";
import { ErrorState, EmptyState } from "../components/States";
import { UserPicker } from "../components/UserPicker";
import { PageHeader } from "../components/ui/PageHeader";
import { Button } from "../components/ui/Button";
import { Banner } from "../components/ui/Banner";
import { Field, fieldInputClasses } from "../components/ui/Field";
import { CopyButton } from "../components/ui/CopyButton";
import { SkeletonTableRows } from "../components/ui/Skeleton";
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

  const [anchors, setAnchors] = useState<AnchorSummary[] | null>(null);
  const [anchorResults, setAnchorResults] = useState<AnchorVerificationResult[] | null>(null);
  const [anchoring, setAnchoring] = useState(false);
  const [anchorVerifying, setAnchorVerifying] = useState(false);
  const [anchorMessage, setAnchorMessage] = useState<string | null>(null);
  const [anchorError, setAnchorError] = useState<string | null>(null);

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

  const loadAnchors = useCallback(() => {
    getAnchors()
      .then(setAnchors)
      .catch(() => setAnchors([]));
  }, []);

  useEffect(() => {
    loadAnchors();
  }, [loadAnchors]);

  async function handleAnchorNow() {
    setAnchoring(true);
    setAnchorError(null);
    setAnchorMessage(null);
    try {
      const result = await anchorNow();
      if (result.outcome === "anchored") {
        setAnchorMessage(`Anchored at head seq ${result.headSeq} (TSA genTime ${new Date(result.genTime).toLocaleString()}).`);
        loadAnchors();
      } else if (result.outcome === "skipped-too-soon") {
        setAnchorMessage(`Too soon since the last anchor — next eligible at ${new Date(result.nextEligibleAt).toLocaleString()}.`);
      } else if (result.outcome === "skipped-empty-chain") {
        setAnchorMessage("Nothing to anchor yet — the audit chain has no entries.");
      }
    } catch (err) {
      setAnchorError(
        axios.isAxiosError(err)
          ? ((err.response?.data as { reason?: string } | undefined)?.reason ?? "Failed to reach the TSA")
          : "Failed to reach the TSA",
      );
    } finally {
      setAnchoring(false);
    }
  }

  async function handleVerifyAnchors() {
    setAnchorVerifying(true);
    setAnchorError(null);
    try {
      const results = await verifyAnchorsApi();
      setAnchorResults(results);
    } catch (err) {
      setAnchorError(
        axios.isAxiosError(err) ? (err.response?.data?.error ?? "Failed to verify anchors") : "Failed to verify anchors",
      );
    } finally {
      setAnchorVerifying(false);
    }
  }

  function tsaHost(url: string): string {
    try {
      return new URL(url).host;
    } catch {
      return url;
    }
  }

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
      <PageHeader
        title="Admin — Certificate Authority"
        subtitle="Revoke a compromised or retired certificate, and review the Certificate Revocation List (CRL). Revoking takes effect immediately across every signing and verification path."
      />

      <Card>
        <h2 className="text-lg font-semibold text-slate-900">Revoke a certificate</h2>
        <form onSubmit={handleRevoke} className="mt-4 flex flex-col gap-4">
          <Field label="User">
            <UserPicker selected={targetUser} onSelect={setTargetUser} placeholder="Search by name…" />
          </Field>

          <Field label="Reason">
            <input
              type="text"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. Private key compromised"
              className={fieldInputClasses}
            />
          </Field>

          {formError && <Banner variant="danger">{formError}</Banner>}
          {successMessage && <Banner variant="success">{successMessage}</Banner>}

          <Button type="submit" loading={submitting} className="self-start">
            {submitting ? "Revoking…" : "Revoke Certificate"}
          </Button>
        </form>
      </Card>

      <Card>
        <h2 className="text-lg font-semibold text-slate-900">Certificate Revocation List (CRL)</h2>
        <p className="mt-1 text-sm text-slate-600">Every certificate revoked so far, most recent first.</p>

        <div className="mt-4">
          {crlError && <ErrorState label={crlError} />}
          {!crlError && crl !== null && crl.length === 0 && (
            <EmptyState label="No certificates have been revoked." />
          )}
          {!crlError && (crl === null || crl.length > 0) && (
            <div className="overflow-x-auto rounded-lg border border-slate-200">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium uppercase tracking-wide text-slate-600">
                    <th className="px-4 py-2.5">Subject</th>
                    <th className="px-4 py-2.5">Role</th>
                    <th className="px-4 py-2.5">Fingerprint</th>
                    <th className="px-4 py-2.5">Revoked at</th>
                    <th className="px-4 py-2.5">Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {crl === null && <SkeletonTableRows rows={3} columns={5} />}
                  {crl?.map((entry) => (
                    <tr key={entry.certificateId} className="border-b border-slate-100 last:border-0">
                      <td className="px-4 py-2.5 text-slate-900">{entry.subjectName}</td>
                      <td className="px-4 py-2.5 text-slate-600">{ROLE_LABELS[entry.role]}</td>
                      <td className="px-4 py-2.5 font-mono text-xs text-slate-500">{entry.fingerprint.slice(0, 16)}…</td>
                      <td className="px-4 py-2.5 text-slate-600">{new Date(entry.revokedAt).toLocaleString()}</td>
                      <td className="px-4 py-2.5 text-slate-600">{entry.revokedReason ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </Card>

      <Card>
        <h2 className="text-lg font-semibold text-slate-900">Verify audit chain integrity</h2>
        <p className="mt-1 text-sm text-slate-600">
          Recomputes every audit log entry's hash and checks its link to the previous entry — a
          tamper anywhere in the chain (edited or deleted row) is reported as the first broken
          sequence number, not just "something's wrong."
        </p>

        <Button onClick={handleVerifyIntegrity} loading={auditChecking} icon={<ShieldCheck className="h-4 w-4" aria-hidden="true" />} className="mt-4 self-start">
          {auditChecking ? "Verifying…" : "Verify integrity"}
        </Button>

        {auditError && (
          <div className="mt-4">
            <ErrorState label={auditError} />
          </div>
        )}

        {auditResult && (
          <div
            className={`mt-4 rounded-xl border p-4 ${
              auditResult.valid ? "border-green-200 bg-green-50" : "border-red-200 bg-red-50"
            }`}
          >
            <div className="flex items-center gap-2">
              {auditResult.valid ? (
                <CheckCircle2 className="h-5 w-5 text-green-600" aria-hidden="true" />
              ) : (
                <XCircle className="h-5 w-5 text-red-600" aria-hidden="true" />
              )}
              <span className={`text-sm font-semibold ${auditResult.valid ? "text-green-800" : "text-red-700"}`}>
                {auditResult.valid ? "Chain valid" : `Chain broken at seq ${auditResult.firstBrokenSeq}`}
              </span>
            </div>
            <p className={`mt-1 text-sm ${auditResult.valid ? "text-green-700" : "text-red-700"}`}>
              {auditResult.valid
                ? `All ${auditResult.checked} entries verified.`
                : `${auditResult.checked} entries verified before the break: ${auditResult.reason}`}
            </p>
            {auditEntryCount !== null && (
              <p className="mt-2 text-sm text-slate-600">Total entries in the log: {auditEntryCount}</p>
            )}
            {auditHead?.hash && (
              <div className="mt-2 flex items-center gap-2">
                <span className="text-sm text-slate-600">Head: seq {auditHead.seq} —</span>
                <span className="truncate font-mono text-xs text-slate-700" title={auditHead.hash}>
                  {auditHead.hash}
                </span>
                <CopyButton value={auditHead.hash} label="Copy head hash" />
              </div>
            )}
          </div>
        )}
      </Card>

      <Card>
        <h2 className="text-lg font-semibold text-slate-900">Trusted timestamp anchors</h2>
        <p className="mt-1 text-sm text-slate-600">
          Periodically anchors the audit chain's head hash with a public RFC 3161 Time-Stamp
          Authority — an independent third party attesting "this hash existed no later than this
          time," on top of (never instead of) the chain's own tamper-evident hash links.
        </p>

        {anchors && anchors.length > 0 ? (
          <p className="mt-3 text-sm text-slate-700">
            Last anchored: <span className="font-medium">{new Date(anchors[0].createdAt).toLocaleString()}</span> by{" "}
            <span className="font-medium">{tsaHost(anchors[0].tsaUrl)}</span>
            {anchors[0].headSeq !== null && <> — covers log entry #{anchors[0].headSeq}</>}
          </p>
        ) : (
          anchors !== null && <p className="mt-3 text-sm text-slate-600">No anchors yet.</p>
        )}

        <div className="mt-4 flex flex-wrap gap-3">
          <Button onClick={handleAnchorNow} loading={anchoring} className="self-start">
            {anchoring ? "Anchoring…" : "Anchor now"}
          </Button>
          <Button variant="secondary" onClick={handleVerifyAnchors} loading={anchorVerifying} className="self-start">
            {anchorVerifying ? "Verifying…" : "Verify anchors"}
          </Button>
        </div>

        {anchorMessage && (
          <p className="mt-3 text-sm text-slate-600">{anchorMessage}</p>
        )}
        {anchorError && (
          <div className="mt-3">
            <ErrorState label={anchorError} />
          </div>
        )}

        {anchorResults && (
          <div className="mt-4 flex flex-col gap-4">
            {anchorResults.length === 0 && <EmptyState label="No anchors to verify yet." />}
            {anchorResults.map((result) => (
              <div
                key={result.anchorId}
                className={`rounded-xl border p-4 ${
                  result.status === "VALID" ? "border-green-200 bg-green-50" : "border-red-200 bg-red-50"
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-slate-900">
                    Anchored {new Date(result.genTime).toLocaleString()} — {tsaHost(result.tsaUrl)}
                  </span>
                  <ValidBadge valid={result.status === "VALID"} label={result.status} />
                </div>
                <ul className="mt-3 flex flex-col divide-y divide-slate-200">
                  {result.steps.map((s) => (
                    <li key={s.id} className="flex items-start justify-between gap-3 py-2">
                      <div>
                        <span className="text-sm font-medium text-slate-900">{s.label}</span>
                        <p className="mt-0.5 text-sm text-slate-600">{s.detail}</p>
                      </div>
                      <ValidBadge valid={s.pass} label={s.pass ? "Pass" : "Fail"} />
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
