import { NavLink } from "react-router-dom";
import { X, type LucideIcon } from "lucide-react";

export interface SidebarNavItem {
  to: string;
  label: string;
  icon: LucideIcon;
}

interface SidebarProps {
  items: SidebarNavItem[];
  mobileOpen: boolean;
  onClose: () => void;
}

function linkClasses(isActive: boolean) {
  return [
    "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
    isActive ? "bg-navy text-white" : "text-slate-600 hover:bg-slate-100 hover:text-slate-900",
  ].join(" ");
}

function NavItems({ items, onNavigate }: { items: SidebarNavItem[]; onNavigate?: () => void }) {
  return (
    <nav className="flex flex-col gap-1">
      {items.map(({ to, label, icon: Icon }) => (
        <NavLink key={to} to={to} onClick={onNavigate} className={({ isActive }) => linkClasses(isActive)}>
          <Icon className="h-4.5 w-4.5" aria-hidden="true" />
          {label}
        </NavLink>
      ))}
    </nav>
  );
}

// Left sidebar navigation for the authenticated dashboard area. Fixed on
// desktop (md+), an off-canvas drawer with a backdrop on mobile —
// `mobileOpen`/`onClose` are owned by Layout.tsx.
export function Sidebar({ items, mobileOpen, onClose }: SidebarProps) {
  return (
    <>
      <aside className="hidden w-60 shrink-0 border-r border-slate-200 bg-white px-3 py-5 md:block">
        <NavItems items={items} />
      </aside>

      {mobileOpen && (
        <div className="fixed inset-0 z-40 md:hidden">
          <div className="absolute inset-0 bg-slate-900/40" onClick={onClose} aria-hidden="true" />
          <div className="absolute inset-y-0 left-0 flex w-64 flex-col gap-4 bg-white px-3 py-5 shadow-lg">
            <button
              type="button"
              onClick={onClose}
              aria-label="Close menu"
              className="ml-auto flex h-8 w-8 items-center justify-center rounded-md text-slate-500 hover:bg-slate-100 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-navy"
            >
              <X className="h-5 w-5" aria-hidden="true" />
            </button>
            <NavItems items={items} onNavigate={onClose} />
          </div>
        </div>
      )}
    </>
  );
}
