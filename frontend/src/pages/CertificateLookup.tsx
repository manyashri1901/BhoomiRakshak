import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import axios from "axios";
import { Search } from "lucide-react";
import { getCertificateByUserId } from "../api/certificates";
import { searchUsers } from "../api/users";
import { Card } from "../components/Card";
import { ValidBadge } from "../components/ValidBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { PageHeader } from "../components/ui/PageHeader";
import { CopyButton } from "../components/ui/CopyButton";
import { fieldInputClasses } from "../components/ui/Field";
import { ROLE_LABELS } from "../lib/roleHome";
import type { Certificate, Role, UserSummary } from "../types";

const ROLES: Role[] = ["LANDOWNER", "VILLAGE_OFFICER", "REGISTRAR"];

function formatDateTime(iso: string) {
  return new Date(iso).toLocaleString();
}

function SearchPanel() {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [role, setRole] = useState<Role | "">("");
  const [results, setResults] = useState<UserSummary[] | null>(null);
  const [searching, setSearching] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setSearching(true);
    const timeout = setTimeout(() => {
      searchUsers({ q: query || undefined, role: role || undefined })
        .then((data) => {
          if (!cancelled) setResults(data);
        })
        .finally(() => {
          if (!cancelled) setSearching(false);
        });
    }, 250);
    return () => {
      cancelled = true;
      clearTimeout(timeout);
    };
  }, [query, role]);

  return (
    <Card>
      <h2 className="text-lg font-semibold text-slate-900">Find a user</h2>
      <p className="mt-1 text-sm text-slate-600">Search by name or filter by role to look up a certificate.</p>
      <div className="mt-4 flex flex-wrap gap-3">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" aria-hidden="true" />
          <input
            type="text"
            placeholder="Search by name…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className={`${fieldInputClasses} w-full pl-9`}
          />
        </div>
        <select
          value={role}
          onChange={(e) => setRole(e.target.value as Role | "")}
          className={fieldInputClasses}
        >
          <option value="">All roles</option>
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {ROLE_LABELS[r]}
            </option>
          ))}
        </select>
      </div>

      <div className="mt-4 flex flex-col gap-1">
        {searching && <p className="text-sm text-slate-500">Searching…</p>}
        {!searching && results !== null && results.length === 0 && (
          <p className="text-sm text-slate-500">No users found.</p>
        )}
        {!searching &&
          results?.map((u) => (
            <button
              key={u.id}
              type="button"
              onClick={() => navigate(`/certificates/${u.id}`)}
              className="flex items-center justify-between rounded-lg px-3 py-2 text-left text-sm hover:bg-slate-50"
            >
              <span className="text-slate-900">{u.name}</span>
              <span className="text-xs uppercase tracking-wide text-slate-500">{ROLE_LABELS[u.role]}</span>
            </button>
          ))}
      </div>
    </Card>
  );
}

export function CertificateLookup() {
  const { userId } = useParams<{ userId: string }>();
  const [certificate, setCertificate] = useState<Certificate | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!userId) {
      setCertificate(null);
      setError(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    getCertificateByUserId(userId)
      .then((data) => {
        if (!cancelled) setCertificate(data);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(
          axios.isAxiosError(err)
            ? (err.response?.data?.error ?? "Failed to load certificate")
            : "Failed to load certificate",
        );
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [userId]);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title="Certificate Lookup" subtitle="Any stakeholder can verify another user's certificate against the CA." />

      {!userId && <SearchPanel />}

      {userId && loading && <LoadingState label="Verifying certificate…" />}
      {userId && error && <ErrorState label={error} />}
      {userId && !loading && !error && certificate === null && (
        <EmptyState label="No certificate found for this user." />
      )}

      {certificate && (
        <Card>
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h2 className="text-xl font-semibold text-slate-900">{certificate.subjectName}</h2>
              <p className="mt-1 text-xs uppercase tracking-wide text-slate-500">{ROLE_LABELS[certificate.role]}</p>
            </div>
            <ValidBadge valid={certificate.valid} label={certificate.valid ? "Certificate Valid" : "Certificate Invalid"} />
          </div>

          <dl className="mt-4 grid grid-cols-1 gap-4 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-slate-500">Issuer</dt>
              <dd className="text-slate-900">{certificate.issuer}</dd>
            </div>
            <div>
              <dt className="text-slate-500">Issued</dt>
              <dd className="text-slate-900">{formatDateTime(certificate.issuedAt)}</dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="text-slate-500">Fingerprint (SHA-256 of public key)</dt>
              <dd className="mt-1 flex items-center gap-1.5">
                <span className="break-all font-mono text-xs text-slate-900">{certificate.fingerprint}</span>
                <CopyButton value={certificate.fingerprint} label="Copy fingerprint" />
              </dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="text-slate-500">Public key</dt>
              <dd className="mt-1 flex items-start gap-1.5">
                <pre className="max-h-40 flex-1 overflow-y-auto whitespace-pre-wrap break-all rounded-lg bg-slate-50 p-3 font-mono text-xs text-slate-900">
                  {certificate.publicKey}
                </pre>
                <CopyButton value={certificate.publicKey} label="Copy public key" />
              </dd>
            </div>
          </dl>

          <Link to="/certificates" className="mt-4 inline-block text-sm font-medium text-navy underline">
            ← Search another user
          </Link>
        </Card>
      )}
    </div>
  );
}
