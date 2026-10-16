// Loading skeletons — shown instead of a bare "Loading…" string while data
// is in flight. Purely decorative placeholders; callers decide when to
// show them based on their own loading state.

export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-skeleton rounded-md bg-slate-200 ${className}`} aria-hidden="true" />;
}

export function SkeletonTableRows({ rows = 4, columns = 4 }: { rows?: number; columns?: number }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, r) => (
        <tr key={r} className="border-b border-slate-200 last:border-0">
          {Array.from({ length: columns }).map((_, c) => (
            <td key={c} className="px-4 py-3">
              <Skeleton className="h-4 w-full max-w-32" />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}

export function SkeletonCard() {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <Skeleton className="h-5 w-40" />
      <Skeleton className="mt-3 h-4 w-full" />
      <Skeleton className="mt-2 h-4 w-3/4" />
    </div>
  );
}
