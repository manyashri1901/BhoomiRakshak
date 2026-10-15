import { useEffect, useRef, useState } from "react";
import { Search } from "lucide-react";
import { searchUsers } from "../api/users";
import { fieldInputClasses } from "./ui/Field";
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
      <div className="flex items-center justify-between rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm">
        <span className="text-slate-900">{selected.name}</span>
        <button
          type="button"
          onClick={() => {
            onSelect(null);
            setQuery("");
          }}
          className="text-xs font-medium text-navy underline"
        >
          Change
        </button>
      </div>
    );
  }

  return (
    <div ref={containerRef} className="relative">
      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" aria-hidden="true" />
        <input
          type="text"
          value={query}
          placeholder={placeholder ?? "Search by name…"}
          onFocus={() => setOpen(true)}
          onChange={(e) => {
            setQuery(e.target.value);
            setOpen(true);
          }}
          className={`${fieldInputClasses} w-full pl-9`}
        />
      </div>
      {open && (
        <div className="absolute z-10 mt-1 max-h-48 w-full overflow-y-auto rounded-lg border border-slate-200 bg-white shadow-md">
          {results.length === 0 && (
            <div className="px-3 py-2 text-sm text-slate-500">
              {/* The server returns [] for any query under 3 characters —
                  an anti-enumeration bound, not a real "no results" case. */}
              {query.trim().length < 3 ? "Type at least 3 characters to search." : "No matches."}
            </div>
          )}
          {results.map((u) => (
            <button
              key={u.id}
              type="button"
              onClick={() => {
                onSelect(u);
                setOpen(false);
              }}
              className="block w-full px-3 py-2 text-left text-sm hover:bg-slate-50"
            >
              {u.name}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
