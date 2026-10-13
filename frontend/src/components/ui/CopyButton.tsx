import { useState } from "react";
import { Check, Copy } from "lucide-react";

// Copies `value` to the clipboard and shows a brief "Copied" confirmation.
// Purely presentational — never touches the value it copies beyond
// clipboard write; no new data is read or fetched.
export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard access can be denied/unavailable (permissions, insecure
      // context) — silently no-op rather than throw into the UI; the
      // value is still visible on screen to copy by hand.
    }
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label={label}
      title={label}
      className="inline-flex shrink-0 items-center justify-center rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-navy"
    >
      {copied ? <Check className="h-3.5 w-3.5 text-green-600" aria-hidden="true" /> : <Copy className="h-3.5 w-3.5" aria-hidden="true" />}
    </button>
  );
}
