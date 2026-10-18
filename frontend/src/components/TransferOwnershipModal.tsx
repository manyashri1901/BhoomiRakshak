import { useState } from "react";
import { ArrowRightLeft } from "lucide-react";
import { prepareCreateTransaction, submitCreateTransaction } from "../api/transactions";
import { uploadDocument } from "../api/documents";
import { signAndSubmit } from "../lib/signAndSubmit";
import { getErrorMessage } from "../lib/errorMessage";
import { useAuth } from "../context/AuthContext";
import { UserPicker } from "./UserPicker";
import { PasswordPrompt } from "./PasswordPrompt";
import { Button } from "./ui/Button";
import { Banner } from "./ui/Banner";
import { Field, fieldInputClasses } from "./ui/Field";
import type { UserSummary } from "../types";

interface TransferOwnershipModalProps {
  landRecordId: string;
  surveyNumber: string;
  onClose: () => void;
  onTransferred: () => void;
}

// Focused single-purpose version of the Landowner dashboard's generic
// "Create Transaction" form, scoped to exactly one land record and one
// transaction type (TRANSFER) — same underlying prepare -> sign -> submit
// machinery (lib/signAndSubmit.ts), just without making the caller pick
// the record or the type themselves.
export function TransferOwnershipModal({
  landRecordId,
  surveyNumber,
  onClose,
  onTransferred,
}: TransferOwnershipModalProps) {
  const { user, wrappedKey } = useAuth();
  const [toOwner, setToOwner] = useState<UserSummary | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [signingOpen, setSigningOpen] = useState(false);
  const [pendingInput, setPendingInput] = useState<{
    landRecordId: string;
    toOwnerId: string;
    documentPath: string;
    documentHash: string;
  } | null>(null);

  async function handleContinue() {
    setFormError(null);
    if (!toOwner) {
      setFormError("Select the new owner.");
      return;
    }
    if (!file) {
      setFormError("Attach a supporting document (PDF, JPEG, or PNG).");
      return;
    }
    setSubmitting(true);
    try {
      const upload = await uploadDocument(file);
      setPendingInput({
        landRecordId,
        toOwnerId: toOwner.id,
        documentPath: upload.documentPath,
        documentHash: upload.documentHash,
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
      () => prepareCreateTransaction({ type: "TRANSFER", ...pendingInput }),
      (nonce, signatureValue) => submitCreateTransaction(nonce, signatureValue),
    );
    setSigningOpen(false);
    onTransferred();
  }

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-slate-900/40 px-4 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-6 shadow-lg">
        <div className="flex items-center gap-2">
          <div className="flex h-9 w-9 items-center justify-center rounded-full bg-navy/10 text-navy">
            <ArrowRightLeft className="h-4.5 w-4.5" aria-hidden="true" />
          </div>
          <h2 className="text-lg font-semibold text-slate-900">Transfer ownership</h2>
        </div>
        <p className="mt-2 text-sm text-slate-600">
          Survey No. {surveyNumber} — sent for Village Officer, then Registrar, review before the
          transfer takes effect.
        </p>

        <div className="mt-4 flex flex-col gap-4">
          <Field label="New owner" helperText="Search by name or exact email — must be a registered Landowner.">
            <UserPicker
              role="LANDOWNER"
              selected={toOwner}
              onSelect={setToOwner}
              excludeUserId={user?.userId}
              placeholder="Search landowners by name or email…"
            />
          </Field>

          <Field label="Supporting document">
            <input
              type="file"
              accept=".pdf,.jpg,.jpeg,.png"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
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
        title="Sign transfer"
        description="Enter your password to unlock your signing key and submit this transfer."
        confirmLabel="Sign & Submit"
        onConfirm={handleSignAndSubmit}
        onCancel={() => setSigningOpen(false)}
      />
    </div>
  );
}
