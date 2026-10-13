import { CheckCircle2, XCircle } from "lucide-react";

export function ValidBadge({ valid, label }: { valid: boolean; label?: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${
        valid ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"
      }`}
    >
      {valid ? (
        <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
      ) : (
        <XCircle className="h-3.5 w-3.5" aria-hidden="true" />
      )}
      {label ?? (valid ? "Valid" : "Invalid")}
    </span>
  );
}
