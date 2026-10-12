import { useState, type FormEvent } from "react";
import { ErrorState } from "./States";

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
      setError(err instanceof Error ? err.message : "Signing failed");
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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 px-4">
      <div className="w-full max-w-sm rounded-lg border border-border-subtle bg-surface p-6 shadow-lg">
        <h2 className="font-serif text-lg font-semibold text-ink">{title}</h2>
        <p className="mt-1 text-sm text-muted">{description}</p>

        <form onSubmit={handleSubmit} className="mt-4 flex flex-col gap-3">
          <label className="flex flex-col gap-1">
            <span className="text-sm font-medium text-ink">Password</span>
            <input
              type="password"
              autoFocus
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="rounded-md border border-border-subtle px-3 py-2 text-sm outline-none focus:border-camel focus:ring-1 focus:ring-camel"
            />
            <span className="text-xs text-muted">
              Used locally to unlock your signing key — never sent to the server.
            </span>
          </label>

          {error && <ErrorState label={error} />}

          <div className="mt-1 flex gap-3">
            <button
              type="submit"
              disabled={submitting}
              className="rounded-md bg-coffee px-4 py-2 text-sm font-semibold text-apricot hover:bg-coffee-hover disabled:cursor-not-allowed disabled:opacity-60"
            >
              {submitting ? "Signing…" : confirmLabel}
            </button>
            <button
              type="button"
              onClick={handleCancel}
              disabled={submitting}
              className="rounded-md border border-border-subtle px-4 py-2 text-sm font-medium text-ink hover:bg-neutral-chip disabled:cursor-not-allowed disabled:opacity-60"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
