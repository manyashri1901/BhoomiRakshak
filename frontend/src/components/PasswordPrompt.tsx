import { useState, type FormEvent } from "react";
import { Lock } from "lucide-react";
import { Banner } from "./ui/Banner";
import { Button } from "./ui/Button";
import { Field, fieldInputClasses } from "./ui/Field";
import { getErrorMessage } from "../lib/errorMessage";

interface PasswordPromptProps {
  open: boolean;
  title: string;
  description: string;
  confirmLabel?: string;
  onConfirm: (password: string) => Promise<void>;
  onCancel: () => void;
}

// A password re-entry modal used at every signing point (transaction
// creation, VO approval, registrar approval): the password never leaves
// the browser — it's used locally to unwrap the user's private key
// (lib/clientCrypto.ts) for exactly the duration of one signature, then
// discarded along with the key. onConfirm is responsible for closing the
// modal (by flipping `open` to false) once its work succeeds; on failure
// it should throw, and the error is shown here without closing.
export function PasswordPrompt({
  open,
  title,
  description,
  confirmLabel = "Sign",
  onConfirm,
  onCancel,
}: PasswordPromptProps) {
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!open) return null;

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await onConfirm(password);
      setPassword("");
    } catch (err) {
      setError(getErrorMessage(err, "Signing failed"));
    } finally {
      setSubmitting(false);
    }
  }

  function handleCancel() {
    setPassword("");
    setError(null);
    onCancel();
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 px-4 backdrop-blur-sm">
      <div className="w-full max-w-sm rounded-xl border border-slate-200 bg-white p-6 shadow-lg">
        <div className="flex items-center gap-2">
          <div className="flex h-9 w-9 items-center justify-center rounded-full bg-navy/10 text-navy">
            <Lock className="h-4.5 w-4.5" aria-hidden="true" />
          </div>
          <h2 className="text-lg font-semibold text-slate-900">{title}</h2>
        </div>
        <p className="mt-2 text-sm text-slate-600">{description}</p>

        <form onSubmit={handleSubmit} className="mt-4 flex flex-col gap-3">
          <Field label="Password" helperText="Used locally to unlock your signing key — never sent to the server.">
            <input
              type="password"
              autoFocus
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={fieldInputClasses}
            />
          </Field>

          {error && <Banner variant="danger">{error}</Banner>}

          <div className="mt-1 flex gap-3">
            <Button type="submit" loading={submitting}>
              {submitting ? "Signing…" : confirmLabel}
            </Button>
            <Button type="button" variant="secondary" onClick={handleCancel} disabled={submitting}>
              Cancel
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
