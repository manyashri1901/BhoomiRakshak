import type { ReactNode } from "react";

type Variant = "neutral" | "warning" | "success" | "danger";

// See index.css for why each chip uses the text color it does — Camel
// fails AA as text on any of these backgrounds, so "success" pairs its
// camel-derived chip with Dark Cocoa text instead.
const VARIANT_CLASSES: Record<Variant, string> = {
  neutral: "bg-neutral-chip text-dark-cocoa",
  warning: "bg-warning-chip text-coffee",
  success: "bg-valid-chip text-dark-cocoa",
  danger: "bg-danger-chip text-wax-seal",
};

export function Badge({ variant = "neutral", children }: { variant?: Variant; children: ReactNode }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium uppercase tracking-wide ${VARIANT_CLASSES[variant]}`}
    >
      {children}
    </span>
  );
}
