import { AlertCircle, Inbox } from "lucide-react";
import { Skeleton } from "./ui/Skeleton";

export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex flex-col gap-2 rounded-xl border border-slate-200 bg-white px-6 py-8">
      <Skeleton className="h-4 w-1/3" />
      <Skeleton className="h-4 w-1/2" />
      <span className="sr-only">{label}</span>
    </div>
  );
}

export function EmptyState({ label }: { label: string }) {
  return (
    <div className="flex flex-col items-center gap-2 rounded-xl border border-dashed border-slate-300 bg-white px-6 py-10 text-center">
      <Inbox className="h-6 w-6 text-slate-400" aria-hidden="true" />
      <p className="text-sm text-slate-600">{label}</p>
    </div>
  );
}

export function ErrorState({ label }: { label: string }) {
  return (
    <div className="flex items-start gap-2 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}
