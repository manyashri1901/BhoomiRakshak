import { WaxSeal } from "./WaxSeal";

// Text color note: Camel fails WCAG AA as text at any size against these
// chip backgrounds (max 3.13:1 — short even of the 3:1 large-text floor),
// so the "valid" badge uses Dark Cocoa for its label (12.15:1 on the camel
// chip) with Camel carried instead by the seal icon and the emboss ring.
// Wax Seal Red passes AA as text directly (7.88:1 on its own chip), so the
// "invalid" badge keeps it as the label color for a stronger danger cue.
export function ValidBadge({ valid, label }: { valid: boolean; label?: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${
        valid ? "bg-valid-chip text-dark-cocoa" : "bg-danger-chip text-wax-seal"
      }`}
    >
      <WaxSeal valid={valid} className="h-3.5 w-3.5" />
      {label ?? (valid ? "Valid" : "Invalid")}
    </span>
  );
}
