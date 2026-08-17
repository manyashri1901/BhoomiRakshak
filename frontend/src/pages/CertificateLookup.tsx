import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import axios from "axios";
import { getCertificateByUserId } from "../api/certificates";
import { searchUsers } from "../api/users";
import { Card } from "../components/Card";
import { ValidBadge } from "../components/ValidBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
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
      <h2 className="font-serif text-lg font-semibold text-ink">Find a user</h2>
      <p className="mt-1 text-sm text-muted">Search by name or filter by role to look up a certificate.</p>
      <div className="mt-4 flex flex-wrap gap-3">
        <input
          type="text"
          placeholder="Search by name…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="flex-1 rounded-md border border-border-subtle px-3 py-2 text-sm outline-none focus:border-camel focus:ring-1 focus:ring-camel"
        />
        <select
          value={role}
          onChange={(e) => setRole(e.target.value as Role | "")}
          className="rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm outline-none focus:border-camel focus:ring-1 focus:ring-camel"
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
        {searching && <p className="text-sm text-muted">Searching…</p>}
        {!searching && results !== null && results.length === 0 && (
          <p className="text-sm text-muted">No users found.</p>
        )}
        {!searching &&
          results?.map((u) => (
            <button
              key={u.id}
              type="button"
              onClick={() => navigate(`/certificates/${u.id}`)}
              className="flex items-center justify-between rounded-md px-3 py-2 text-left text-sm hover:bg-neutral-chip"
            >
              <span className="text-ink">{u.name}</span>
              <span className="text-xs uppercase tracking-wide text-muted">
                {ROLE_LABELS[u.role]}
              </span>
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
      <div>
        <h1 className="font-serif text-2xl font-semibold text-ink">Certificate Lookup</h1>
        <p className="mt-1 text-sm text-muted">
          Any stakeholder can verify another user's certificate against the CA.
        </p>
      </div>

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
              <h2 className="font-serif text-xl font-semibold text-ink">{certificate.subjectName}</h2>
              <p className="mt-1 text-xs uppercase tracking-wide text-muted">
                {ROLE_LABELS[certificate.role]}
              </p>
            </div>
            <ValidBadge valid={certificate.valid} label={certificate.valid ? "Certificate Valid" : "Certificate Invalid"} />
          </div>

          <dl className="mt-4 grid grid-cols-1 gap-4 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-muted">Issuer</dt>
              <dd className="text-ink">{certificate.issuer}</dd>
            </div>
            <div>
              <dt className="text-muted">Issued</dt>
              <dd className="text-ink">{formatDateTime(certificate.issuedAt)}</dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="text-muted">Fingerprint (SHA-256 of public key)</dt>
              <dd className="break-all font-mono text-xs text-ink">{certificate.fingerprint}</dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="text-muted">Public key</dt>
              <dd className="mt-1 max-h-40 overflow-y-auto rounded-md bg-neutral-chip p-3 font-mono text-xs break-all text-ink">
                {certificate.publicKey}
              </dd>
            </div>
          </dl>

          <Link to="/certificates" className="mt-4 inline-block text-sm font-medium text-ink underline">
            ← Search another user
          </Link>
        </Card>
      )}
    </div>
  );
}
