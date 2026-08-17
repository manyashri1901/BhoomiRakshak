import { useEffect, useRef, useState } from "react";
import { searchUsers } from "../api/users";
import type { Role, UserSummary } from "../types";

interface UserPickerProps {
  role?: Role;
  placeholder?: string;
  selected: UserSummary | null;
  onSelect: (user: UserSummary | null) => void;
}

// Small debounced-search combobox. Used both by the Registrar's "select
// owner" (LANDOWNER-filtered) and the Landowner's TRANSFER "select new
// owner" pickers, so it isn't tied to either.
export function UserPicker({ role, placeholder, selected, onSelect }: UserPickerProps) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<UserSummary[]>([]);
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const timeout = setTimeout(() => {
      searchUsers({ role, q: query || undefined }).then(setResults);
    }, 200);
    return () => clearTimeout(timeout);
  }, [query, role, open]);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  if (selected) {
    return (
      <div className="flex items-center justify-between rounded-md border border-border-subtle px-3 py-2 text-sm">
        <span className="text-ink">{selected.name}</span>
        <button
          type="button"
          onClick={() => {
            onSelect(null);
            setQuery("");
          }}
          className="text-xs font-medium text-ink underline"
        >
          Change
        </button>
      </div>
    );
  }

  return (
    <div ref={containerRef} className="relative">
      <input
        type="text"
        value={query}
        placeholder={placeholder ?? "Search by name…"}
        onFocus={() => setOpen(true)}
        onChange={(e) => {
          setQuery(e.target.value);
          setOpen(true);
        }}
        className="w-full rounded-md border border-border-subtle px-3 py-2 text-sm outline-none focus:border-camel focus:ring-1 focus:ring-camel"
      />
      {open && (
        <div className="absolute z-10 mt-1 max-h-48 w-full overflow-y-auto rounded-md border border-border-subtle bg-surface shadow-md">
          {results.length === 0 && <div className="px-3 py-2 text-sm text-muted">No matches.</div>}
          {results.map((u) => (
            <button
              key={u.id}
              type="button"
              onClick={() => {
                onSelect(u);
                setOpen(false);
              }}
              className="block w-full px-3 py-2 text-left text-sm hover:bg-neutral-chip"
            >
              {u.name}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
