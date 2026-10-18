import { useEffect, useRef, useState } from "react";
import { HeartHandshake, Search } from "lucide-react";
import { searchLandRecords, type LandRecordSearchResult } from "../api/landRecords";
import { prepareCreateTransaction, submitCreateTransaction } from "../api/transactions";
import { uploadDocument } from "../api/documents";
import { signAndSubmit } from "../lib/signAndSubmit";
import { getErrorMessage } from "../lib/errorMessage";
import { useAuth } from "../context/AuthContext";
import { PasswordPrompt } from "./PasswordPrompt";
import { Button } from "./ui/Button";
import { Banner } from "./ui/Banner";
import { Field, fieldInputClasses } from "./ui/Field";

interface ClaimHeirModalProps {
  onClose: () => void;
  onClaimed: () => void;
}

// A heir's claim is a SUCCESSION transaction on a record they do NOT
// currently own (routes/transactions.ts enforces this) — so, unlike
// TransferOwnershipModal, this starts with finding that record rather than
// picking from the caller's own list.
export function ClaimHeirModal({ onClose, onClaimed }: ClaimHeirModalProps) {
  const { wrappedKey } = useAuth();
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<LandRecordSearchResult[]>([]);
  const [selected, setSelected] = useState<LandRecordSearchResult | null>(null);
  const [deathCertFile, setDeathCertFile] = useState<File | null>(null);
  const [heirDocFile, setHeirDocFile] = useState<File | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [signingOpen, setSigningOpen] = useState(false);
  const [pendingInput, setPendingInput] = useState<{
    landRecordId: string;
    documentPath: string;
    documentHash: string;
    secondaryDocumentPath?: string;
    secondaryDocumentHash?: string;
  } | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (selected || query.trim().length < 3) {
      setResults([]);
      return;
    }
    const timeout = setTimeout(() => {
      searchLandRecords(query.trim()).then(setResults);
    }, 200);
    return () => clearTimeout(timeout);
  }, [query, selected]);

  async function handleContinue() {
    setFormError(null);
    if (!selected) {
      setFormError("Find and select the land record you're claiming.");
      return;
    }
    if (!deathCertFile) {
      setFormError("A death certificate (PDF, JPEG, or PNG) is required.");
      return;
    }
    setSubmitting(true);
    try {
      const deathCertUpload = await uploadDocument(deathCertFile);
      const heirDocUpload = heirDocFile ? await uploadDocument(heirDocFile) : null;
      setPendingInput({
        landRecordId: selected.id,
        documentPath: deathCertUpload.documentPath,
        documentHash: deathCertUpload.documentHash,
        secondaryDocumentPath: heirDocUpload?.documentPath,
        secondaryDocumentHash: heirDocUpload?.documentHash,
      });
      setSigningOpen(true);
    } catch (err) {
      setFormError(getErrorMessage(err, "Failed to upload document"));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleSignAndSubmit(password: string) {
    if (!pendingInput) return;
    if (!wrappedKey) {
      throw new Error("No signing key on this account — log out and back in, or re-register.");
    }
    await signAndSubmit(
      wrappedKey,
      password,
      () => prepareCreateTransaction({ type: "SUCCESSION", ...pendingInput }),
      (nonce, signatureValue) => submitCreateTransaction(nonce, signatureValue),
    );
    setSigningOpen(false);
    onClaimed();
  }

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-slate-900/40 px-4 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-6 shadow-lg">
        <div className="flex items-center gap-2">
          <div className="flex h-9 w-9 items-center justify-center rounded-full bg-navy/10 text-navy">
            <HeartHandshake className="h-4.5 w-4.5" aria-hidden="true" />
          </div>
          <h2 className="text-lg font-semibold text-slate-900">Claim as legal heir</h2>
        </div>
        <p className="mt-2 text-sm text-slate-600">
          Sent for Village Officer, then Registrar, review — same approval chain as a transfer.
        </p>

        <div className="mt-4 flex flex-col gap-4">
          <Field label="Land record" helperText="Search by survey number.">
            {selected ? (
              <div className="flex items-center justify-between rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm">
                <span>
                  <span className="font-medium text-slate-900">{selected.surveyNumber}</span>
                  <span className="ml-2 text-slate-500">
                    {selected.location} — owned by {selected.currentOwnerName}
                  </span>
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setSelected(null);
                    setQuery("");
                  }}
                  className="text-xs font-medium text-navy underline"
                >
                  Change
                </button>
              </div>
            ) : (
              <div ref={containerRef} className="relative">
                <div className="relative">
                  <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" aria-hidden="true" />
                  <input
                    type="text"
                    value={query}
                    placeholder="e.g. SN-2024-001"
                    onChange={(e) => setQuery(e.target.value)}
                    className={`${fieldInputClasses} w-full pl-9`}
                  />
                </div>
                {query.trim().length > 0 && (
                  <div className="absolute z-10 mt-1 max-h-48 w-full overflow-y-auto rounded-lg border border-slate-200 bg-white shadow-md">
                    {results.length === 0 && (
                      <div className="px-3 py-2 text-sm text-slate-500">
                        {query.trim().length < 3 ? "Type at least 3 characters to search." : "No matches."}
                      </div>
                    )}
                    {results.map((r) => (
                      <button
                        key={r.id}
                        type="button"
                        onClick={() => setSelected(r)}
                        className="block w-full px-3 py-2 text-left text-sm hover:bg-slate-50"
                      >
                        <span className="font-medium text-slate-900">{r.surveyNumber}</span>
                        <span className="ml-2 text-slate-500">
                          {r.location} — owned by {r.currentOwnerName}
                        </span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
          </Field>

          <Field label="Death certificate" helperText="Required — PDF, JPEG, or PNG.">
            <input
              type="file"
              accept=".pdf,.jpg,.jpeg,.png"
              onChange={(e) => setDeathCertFile(e.target.files?.[0] ?? null)}
              className={`${fieldInputClasses} file:mr-3 file:rounded-md file:border-0 file:bg-slate-100 file:px-3 file:py-1 file:text-sm file:font-medium file:text-slate-700`}
            />
          </Field>

          <Field label="Legal-heir / succession document" helperText="Optional — PDF, JPEG, or PNG.">
            <input
              type="file"
              accept=".pdf,.jpg,.jpeg,.png"
              onChange={(e) => setHeirDocFile(e.target.files?.[0] ?? null)}
              className={`${fieldInputClasses} file:mr-3 file:rounded-md file:border-0 file:bg-slate-100 file:px-3 file:py-1 file:text-sm file:font-medium file:text-slate-700`}
            />
          </Field>

          {formError && <Banner variant="danger">{formError}</Banner>}

          <div className="mt-1 flex gap-3">
            <Button loading={submitting} onClick={handleContinue}>
              {submitting ? "Uploading…" : "Continue to Sign"}
            </Button>
            <Button type="button" variant="secondary" onClick={onClose} disabled={submitting}>
              Cancel
            </Button>
          </div>
        </div>
      </div>

      <PasswordPrompt
        open={signingOpen}
        title="Sign succession claim"
        description="Enter your password to unlock your signing key and submit this claim."
        confirmLabel="Sign & Submit"
        onConfirm={handleSignAndSubmit}
        onCancel={() => setSigningOpen(false)}
      />
    </div>
  );
}
