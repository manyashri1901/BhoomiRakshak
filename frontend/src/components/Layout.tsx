import { useEffect, useRef, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import {
  ChevronDown,
  Database,
  FileBadge2,
  LogOut,
  Menu,
  SearchCheck,
  ShieldCheck,
  Stamp,
  Home,
  ClipboardCheck,
  X,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { roleHomePath, ROLE_LABELS } from "../lib/roleHome";
import { Sidebar, type SidebarNavItem } from "./ui/Sidebar";
import { ScrollProgressBar } from "./ui/ScrollProgressBar";
import type { Role } from "../types";

const ROLE_HOME_NAV: Record<Role, SidebarNavItem> = {
  LANDOWNER: { to: "/landowner", label: "My Land", icon: Home },
  VILLAGE_OFFICER: { to: "/village-officer", label: "Review Queue", icon: ClipboardCheck },
  REGISTRAR: { to: "/registrar", label: "Registrar Queue", icon: Stamp },
  ADMIN: { to: "/admin", label: "Admin", icon: ShieldCheck },
};

const COMMON_NAV: SidebarNavItem[] = [
  { to: "/land-records", label: "Registry", icon: Database },
  { to: "/certificates", label: "Certificates", icon: FileBadge2 },
  { to: "/verify", label: "Verify", icon: SearchCheck },
];

const PUBLIC_NAV = [
  { to: "/", label: "Home", end: true },
  { to: "/how-it-works", label: "How it works", end: false },
  { to: "/verify", label: "Verify a record", end: false },
];

const PUBLIC_FOOTER_LINKS = [
  { to: "/", label: "Home" },
  { to: "/how-it-works", label: "How it works" },
  { to: "/verify", label: "Verify" },
  { to: "/login", label: "Login" },
];

function Logo() {
  return (
    <svg viewBox="0 0 24 24" className="h-6 w-6 text-navy" aria-hidden="true">
      <path
        d="M12 2.5l7.5 3.2v5.1c0 5-3.2 8.9-7.5 10.7-4.3-1.8-7.5-5.7-7.5-10.7V5.7L12 2.5z"
        fill="currentColor"
        opacity="0.12"
      />
      <path
        d="M12 2.5l7.5 3.2v5.1c0 5-3.2 8.9-7.5 10.7-4.3-1.8-7.5-5.7-7.5-10.7V5.7L12 2.5z"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="M9 12.2l2.1 2.1L15.5 10"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function navLinkClasses(isActive: boolean) {
  return [
    "text-sm font-medium transition-colors",
    isActive ? "text-navy" : "text-slate-600 hover:text-slate-900",
  ].join(" ");
}

function UserMenu() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  if (!user) return null;

  function handleLogout() {
    // Navigate before clearing the user, not after: ProtectedRoute is still
    // mounted (we're still on a protected route) at the instant logout()
    // flips user to null, and it reacts by redirecting to /login itself —
    // with `state: { from: <this protected route> }` attached. If that
    // fires, it wins the race against our own state-less navigate() call
    // below, so the next login (possibly a different user) gets redirected
    // right back to the page we just logged out of. Navigating away first
    // unmounts ProtectedRoute before user ever becomes null, so it never
    // gets the chance to attach that stale state.
    navigate("/login", { replace: true });
    logout();
  }

  return (
    <div ref={containerRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-left hover:bg-slate-100 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-navy"
      >
        <div className="flex h-8 w-8 items-center justify-center rounded-full bg-navy text-xs font-semibold text-white">
          {user.name.slice(0, 1).toUpperCase()}
        </div>
        <div className="hidden leading-tight sm:block">
          <div className="text-sm font-medium text-slate-900">{user.name}</div>
          <div className="text-xs text-slate-500">{ROLE_LABELS[user.role]}</div>
        </div>
        <ChevronDown className="h-4 w-4 text-slate-400" aria-hidden="true" />
      </button>

      {open && (
        <div className="absolute right-0 z-20 mt-1 w-44 rounded-lg border border-slate-200 bg-white py-1 shadow-md">
          <button
            type="button"
            onClick={handleLogout}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-slate-700 hover:bg-slate-50"
          >
            <LogOut className="h-4 w-4" aria-hidden="true" />
            Log out
          </button>
        </div>
      )}
    </div>
  );
}

function PublicNav() {
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();

  // Close the mobile menu on every navigation rather than leaving it open
  // behind the new page.
  useEffect(() => {
    setMenuOpen(false);
  }, [location.pathname]);

  return (
    <>
      <nav className="hidden items-center gap-6 md:flex">
        {PUBLIC_NAV.map(({ to, label, end }) => (
          <NavLink key={to} to={to} end={end} className={({ isActive }) => navLinkClasses(isActive)}>
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="ml-auto hidden items-center gap-3 md:flex">
        <NavLink to="/login" className={({ isActive }) => navLinkClasses(isActive)}>
          Login
        </NavLink>
        <Link
          to="/register"
          className="rounded-lg bg-navy px-3.5 py-1.5 text-sm font-medium text-white hover:bg-navy-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-navy"
        >
          Get started
        </Link>
      </div>

      <button
        type="button"
        onClick={() => setMenuOpen((o) => !o)}
        aria-label={menuOpen ? "Close menu" : "Open menu"}
        aria-expanded={menuOpen}
        className="ml-auto flex h-9 w-9 items-center justify-center rounded-lg text-slate-600 hover:bg-slate-100 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-navy md:hidden"
      >
        {menuOpen ? <X className="h-5 w-5" aria-hidden="true" /> : <Menu className="h-5 w-5" aria-hidden="true" />}
      </button>

      {menuOpen && (
        <div className="absolute inset-x-0 top-full z-20 border-b border-slate-200 bg-white px-4 py-3 shadow-md md:hidden">
          <nav className="flex flex-col gap-1">
            {PUBLIC_NAV.map(({ to, label, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) =>
                  `rounded-lg px-3 py-2 text-sm font-medium ${isActive ? "bg-navy/5 text-navy" : "text-slate-700 hover:bg-slate-50"}`
                }
              >
                {label}
              </NavLink>
            ))}
            <div className="mt-2 flex flex-col gap-2 border-t border-slate-200 pt-3">
              <NavLink to="/login" className="rounded-lg px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50">
                Login
              </NavLink>
              <Link
                to="/register"
                className="rounded-lg bg-navy px-3 py-2 text-center text-sm font-medium text-white hover:bg-navy-hover"
              >
                Get started
              </Link>
            </div>
          </nav>
        </div>
      )}
    </>
  );
}

function PublicFooter() {
  return (
    <footer className="border-t border-slate-200 bg-white py-8">
      <div className="mx-auto flex max-w-300 flex-col items-center gap-3 px-4 text-center sm:px-6">
        <div className="text-sm font-semibold text-slate-900">BhoomiRakshak</div>
        <p className="max-w-md text-xs text-slate-500">
          PKI-based secure land record and ownership management — every transaction signed,
          every record independently verifiable.
        </p>
        <nav className="flex flex-wrap items-center justify-center gap-x-5 gap-y-1">
          {PUBLIC_FOOTER_LINKS.map(({ to, label }) => (
            <Link key={to} to={to} className="text-xs font-medium text-slate-600 hover:text-slate-900">
              {label}
            </Link>
          ))}
        </nav>
        <p className="text-xs text-slate-400">Demo prototype</p>
      </div>
    </footer>
  );
}

export function Layout() {
  const { user } = useAuth();
  const location = useLocation();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [location.pathname]);

  const sidebarItems: SidebarNavItem[] = user ? [ROLE_HOME_NAV[user.role], ...COMMON_NAV] : [];

  return (
    <div className="flex min-h-screen flex-col bg-slate-50">
      <ScrollProgressBar />

      <header className="sticky top-0 z-30 border-b border-slate-200 bg-white/90 backdrop-blur supports-backdrop-filter:bg-white/80">
        <div className="relative mx-auto flex max-w-300 items-center gap-4 px-4 py-3 sm:px-6">
          {user && (
            <button
              type="button"
              onClick={() => setMobileNavOpen(true)}
              aria-label="Open menu"
              className="flex h-9 w-9 items-center justify-center rounded-lg text-slate-600 hover:bg-slate-100 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-navy md:hidden"
            >
              <Menu className="h-5 w-5" aria-hidden="true" />
            </button>
          )}

          <Link
            to={user ? roleHomePath(user.role) : "/"}
            className="flex items-center gap-2 text-lg font-semibold text-slate-900"
          >
            <Logo />
            BhoomiRakshak
          </Link>

          {user ? (
            <div className="ml-auto flex items-center gap-3">
              <UserMenu />
            </div>
          ) : (
            <PublicNav />
          )}
        </div>
      </header>

      <div className="mx-auto flex w-full max-w-300 flex-1">
        {user && <Sidebar items={sidebarItems} mobileOpen={mobileNavOpen} onClose={() => setMobileNavOpen(false)} />}

        <main className="w-full min-w-0 flex-1 px-4 py-8 sm:px-6">
          <div key={location.pathname} className="animate-route-fade">
            <Outlet />
          </div>
        </main>
      </div>

      {user ? (
        <footer className="border-t border-slate-200 bg-white py-4 text-center text-xs text-slate-500">
          BhoomiRakshak — PKI-based Secure Land Record &amp; Ownership Management System
        </footer>
      ) : (
        <PublicFooter />
      )}
    </div>
  );
}
