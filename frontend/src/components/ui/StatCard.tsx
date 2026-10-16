import type { LucideIcon } from "lucide-react";

type Tone = "navy" | "teal" | "success" | "warning" | "danger" | "neutral";

const TONE_CLASSES: Record<Tone, string> = {
  navy: "bg-navy/10 text-navy",
  teal: "bg-teal/10 text-teal",
  success: "bg-green-100 text-green-700",
  warning: "bg-amber-100 text-amber-700",
  danger: "bg-red-100 text-red-700",
  neutral: "bg-slate-100 text-slate-600",
};

interface StatCardProps {
  label: string;
  value: string | number;
  icon: LucideIcon;
  tone?: Tone;
}

// Summary stat card shown at the top of a dashboard (e.g. "Pending: 3").
// Display-only — callers compute `value` from data they already fetched.
export function StatCard({ label, value, icon: Icon, tone = "navy" }: StatCardProps) {
  return (
    <div className="flex items-center gap-4 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-lg ${TONE_CLASSES[tone]}`}>
        <Icon className="h-5 w-5" aria-hidden="true" />
      </div>
      <div>
        <div className="text-2xl font-semibold text-slate-900">{value}</div>
        <div className="text-sm text-slate-600">{label}</div>
      </div>
    </div>
  );
}
