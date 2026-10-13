import { AlertTriangle, CheckCircle2, Info, XCircle } from "lucide-react";
import type { ReactNode } from "react";

type Variant = "success" | "danger" | "warning" | "info";

const VARIANT_CLASSES: Record<Variant, string> = {
  success: "bg-green-50 text-green-800 border-green-200",
  danger: "bg-red-50 text-red-700 border-red-200",
  warning: "bg-amber-50 text-amber-800 border-amber-200",
  info: "bg-slate-50 text-slate-700 border-slate-200",
};

const VARIANT_ICON: Record<Variant, typeof CheckCircle2> = {
  success: CheckCircle2,
  danger: XCircle,
  warning: AlertTriangle,
  info: Info,
};

// Inline, non-dismissible status message — used in place of a browser
// alert()/confirm() anywhere a form or action needs to tell the user what
// happened. Purely presentational: callers still own the state that
// decides whether/what to render.
export function Banner({ variant = "info", children }: { variant?: Variant; children: ReactNode }) {
  const Icon = VARIANT_ICON[variant];
  return (
    <div className={`flex items-start gap-2 rounded-lg border px-3 py-2.5 text-sm ${VARIANT_CLASSES[variant]}`}>
      <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <span>{children}</span>
    </div>
  );
}
