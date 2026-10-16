import type { ReactNode } from "react";

interface FieldProps {
  label: string;
  helperText?: string;
  error?: string | null;
  children: ReactNode;
}

// Labelled-input wrapper: label + the input/select/textarea itself (passed
// as children, untouched) + optional helper text + inline validation
// message. Purely a layout/styling wrapper — every existing input, its
// value/onChange/required/etc., stays exactly as the caller wrote it.
export function Field({ label, helperText, error, children }: FieldProps) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-sm font-medium text-slate-700">{label}</span>
      {children}
      {helperText && !error && <span className="text-xs text-slate-500">{helperText}</span>}
      {error && <span className="text-xs font-medium text-red-600">{error}</span>}
    </label>
  );
}

// Shared input classes so every text/number/select/textarea field looks
// identical without re-typing the class string at each call site.
export const fieldInputClasses =
  "rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 outline-none transition-colors placeholder:text-slate-400 focus:border-teal focus:ring-2 focus:ring-teal/30 disabled:cursor-not-allowed disabled:bg-slate-50";
