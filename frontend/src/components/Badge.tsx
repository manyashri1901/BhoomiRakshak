import type { ReactNode } from "react";

type Variant = "neutral" | "warning" | "success" | "danger";

const VARIANT_CLASSES: Record<Variant, string> = {
  neutral: "bg-slate-100 text-slate-600",
  warning: "bg-amber-100 text-amber-700",
  success: "bg-green-100 text-green-700",
  danger: "bg-red-100 text-red-700",
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
