export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 rounded-lg border border-border-subtle bg-surface px-6 py-8 text-sm text-muted">
      <span className="h-3 w-3 animate-pulse rounded-full bg-camel" aria-hidden="true" />
      {label}
    </div>
  );
}

export function EmptyState({ label }: { label: string }) {
  return (
    <div className="rounded-lg border border-dashed border-border-subtle bg-surface px-6 py-8 text-center text-sm text-muted">
      {label}
    </div>
  );
}

export function ErrorState({ label }: { label: string }) {
  return (
    <div className="rounded-lg border border-danger-chip bg-danger-chip px-6 py-4 text-sm text-wax-seal">
      {label}
    </div>
  );
}
