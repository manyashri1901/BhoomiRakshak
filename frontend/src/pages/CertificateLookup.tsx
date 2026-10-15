import { useEffect, useState, type FormEvent } from "react";
import axios from "axios";
import { Search, ShieldCheck } from "lucide-react";
import {
  getCAInfo,
  getCertificateBySerial,
  getSignedCRL,
  searchCertificates,
  type CAInfo,
  type CertificateSearchResult,
} from "../api/certificates";
import {
  verifyCertificateClientSide,
  type CertificateEnvelope,
  type VerifyResult,
} from "../lib/certificateVerify";
import { Card } from "../components/Card";
import { ValidBadge } from "../components/ValidBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { PageHeader } from "../components/ui/PageHeader";
import { CopyButton } from "../components/ui/CopyButton";
import { Banner } from "../components/ui/Banner";
import { fieldInputClasses } from "../components/ui/Field";
import { useAuth } from "../context/AuthContext";
import { ROLE_LABELS } from "../lib/roleHome";

const SEARCHABLE_ROLES = ["VILLAGE_OFFICER", "REGISTRAR", "ADMIN"];
const SEARCH_MIN_LENGTH = 3;

function CAFingerprintNote({ caInfo }: { caInfo: CAInfo | null }) {
  return (
    <Card>
      <div className="flex items-center gap-2">
        <ShieldCheck className="h-4.5 w-4.5 text-teal" aria-hidden="true" />
        <h2 className="text-sm font-semibold text-slate-900">Root CA public key</h2>
      </div>
      {!caInfo && <p className="mt-2 text-sm text-slate-500">Loading…</p>}
      {caInfo && (
        <>
          <div className="mt-2 flex items-start gap-1.5">
            <span className="break-all font-mono text-xs text-slate-600" title={caInfo.fingerprint}>
              {caInfo.fingerprint}
            </span>
            <CopyButton value={caInfo.fingerprint} label="Copy CA public key fingerprint" />
          </div>
          <p className="mt-2 text-sm text-slate-500">
            Every check below verifies against this exact key, fetched from this same server. That
            is a convenience for this prototype, not a complete trust story — in a production
            deployment the CA's public key (or this fingerprint) would be pinned into the client
            application or OS trust store out-of-band, not fetched live from the server it's meant
            to be checking.
          </p>
        </>
      )}
    </Card>
  );
}

function NameSearchPanel({ onPicked }: { onPicked: (serial: string) => void }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<CertificateSearchResult[] | null>(null);
  const [searching, setSearching] = useState(false);

  useEffect(() => {
    if (query.trim().length < SEARCH_MIN_LENGTH) {
      setResults(null);
      return;
    }
    let cancelled = false;
    setSearching(true);
    const timeout = setTimeout(() => {
      searchCertificates({ q: query.trim() })
        .then((data) => {
          if (!cancelled) setResults(data.results);
        })
        .finally(() => {
          if (!cancelled) setSearching(false);
        });
    }, 250);
    return () => {
      cancelled = true;
      clearTimeout(timeout);
    };
  }, [query]);

  return (
    <Card>
      <h2 className="text-lg font-semibold text-slate-900">Search by name</h2>
      <p className="mt-1 text-sm text-slate-600">
        Restricted to Village Officer, Registrar, and Admin accounts — a Landowner only ever
        verifies a specific certificate they already have the serial for.
      </p>
      <div className="relative mt-4">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" aria-hidden="true" />
        <input
          type="text"
          placeholder="Type at least 3 characters…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className={`${fieldInputClasses} w-full pl-9`}
        />
      </div>

      <div className="mt-3 flex flex-col gap-1">
        {query.trim().length > 0 && query.trim().length < SEARCH_MIN_LENGTH && (
          <p className="text-sm text-slate-500">Type at least 3 characters to search.</p>
        )}
        {searching && <p className="text-sm text-slate-500">Searching…</p>}
        {!searching && results !== null && results.length === 0 && (
          <p className="text-sm text-slate-500">No matches.</p>
        )}
        {!searching &&
          results?.map((r) => (
            <button
              key={r.serial}
              type="button"
              onClick={() => onPicked(r.serial)}
              className="flex items-center justify-between rounded-lg px-3 py-2 text-left text-sm hover:bg-slate-50"
            >
              <span className="text-slate-900">{r.name}</span>
              <span className="text-xs uppercase tracking-wide text-slate-500">{ROLE_LABELS[r.role]}</span>
            </button>
          ))}
      </div>
    </Card>
  );
}

function VerifyStepsList({ result }: { result: VerifyResult }) {
  return (
    <ul className="mt-3 flex flex-col divide-y divide-slate-100">
      {result.steps.map((s) => (
        <li key={s.id} className="flex items-start justify-between gap-3 py-2.5">
          <div>
            <span className="text-sm font-medium text-slate-900">{s.label}</span>
            <p className="mt-0.5 text-sm text-slate-600">{s.detail}</p>
          </div>
          <ValidBadge valid={s.pass} label={s.pass ? "Pass" : "Fail"} />
        </li>
      ))}
    </ul>
  );
}

export function CertificateLookup() {
  const { user } = useAuth();
  const canSearchByName = user ? SEARCHABLE_ROLES.includes(user.role) : false;

  const [caInfo, setCaInfo] = useState<CAInfo | null>(null);
  const [serialInput, setSerialInput] = useState("");
  const [certificate, setCertificate] = useState<CertificateEnvelope | null>(null);
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getCAInfo().then(setCaInfo);
  }, []);

  async function runLookup(serial: string) {
    setLoading(true);
    setError(null);
    setCertificate(null);
    setVerifyResult(null);
    try {
      const [cert, ca, crl] = await Promise.all([
        getCertificateBySerial(serial),
        caInfo ? Promise.resolve(caInfo) : getCAInfo(),
        getSignedCRL(),
      ]);
      if (!caInfo) setCaInfo(ca);
      setCertificate(cert);
      // Every verdict shown below is computed HERE, in the browser, from
      // the raw signed data just fetched — never from anything the server
      // itself might claim about validity.
      const result = await verifyCertificateClientSide(cert, ca.publicKey, crl);
      setVerifyResult(result);
    } catch (err) {
      setError(
        axios.isAxiosError(err)
          ? (err.response?.data?.error ?? "Failed to load certificate")
          : "Failed to load certificate",
      );
    } finally {
      setLoading(false);
    }
  }

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!serialInput.trim()) return;
    runLookup(serialInput.trim());
  }

  function handlePicked(serial: string) {
    setSerialInput(serial);
    runLookup(serial);
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Certificate Lookup"
        subtitle="Every check below is verified in your browser against the CA's public key and a signed revocation list — not a status computed by the server."
      />

      <CAFingerprintNote caInfo={caInfo} />

      <Card>
        <h2 className="text-lg font-semibold text-slate-900">Look up by serial</h2>
        <p className="mt-1 text-sm text-slate-600">
          Enter the exact certificate serial (its own id) to verify it independently.
        </p>
        <form onSubmit={handleSubmit} className="mt-4 flex flex-wrap items-end gap-3">
          <label className="flex min-w-64 flex-1 flex-col gap-1.5">
            <span className="text-sm font-medium text-slate-700">Certificate serial / ID</span>
            <input
              type="text"
              required
              value={serialInput}
              onChange={(e) => setSerialInput(e.target.value)}
              placeholder="e.g. cm0abc123…"
              className={`${fieldInputClasses} font-mono`}
            />
          </label>
          <button
            type="submit"
            disabled={loading}
            className="rounded-lg bg-navy px-4 py-2 text-sm font-semibold text-white hover:bg-navy-hover disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? "Verifying…" : "Verify"}
          </button>
        </form>
      </Card>

      {canSearchByName && <NameSearchPanel onPicked={handlePicked} />}

      {loading && <LoadingState label="Verifying certificate…" />}
      {error && <ErrorState label={error} />}
      {!loading && !error && !certificate && (
        <EmptyState label="Enter a certificate serial above to verify it." />
      )}

      {certificate && verifyResult && (
        <Card>
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h2 className="text-xl font-semibold text-slate-900">{certificate.name}</h2>
              <p className="mt-1 text-xs uppercase tracking-wide text-slate-500">
                {ROLE_LABELS[certificate.role as keyof typeof ROLE_LABELS] ?? certificate.role}
              </p>
            </div>
            <ValidBadge
              valid={verifyResult.valid}
              label={verifyResult.valid ? "Certificate Valid" : "Certificate Invalid"}
            />
          </div>

          {!verifyResult.valid && verifyResult.failingStep && (
            <div className="mt-4">
              <Banner variant="danger">
                Failed at the <strong>{verifyResult.steps.find((s) => s.id === verifyResult.failingStep)?.label}</strong> step.
              </Banner>
            </div>
          )}

          <VerifyStepsList result={verifyResult} />

          <dl className="mt-4 grid grid-cols-1 gap-4 border-t border-slate-200 pt-4 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-slate-500">Issuer</dt>
              <dd className="text-slate-900">{certificate.issuer}</dd>
            </div>
            <div>
              <dt className="text-slate-500">Serial</dt>
              <dd className="flex items-center gap-1.5 font-mono text-xs text-slate-900">
                {certificate.serial}
                <CopyButton value={certificate.serial} label="Copy serial" />
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
        </Card>
      )}
    </div>
  );
}
