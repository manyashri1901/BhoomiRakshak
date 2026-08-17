import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { roleHomePath, ROLE_LABELS } from "../lib/roleHome";
import type { Role } from "../types";

const ROLE_NAV: Record<Role, { to: string; label: string }> = {
  LANDOWNER: { to: "/landowner", label: "My Land" },
  VILLAGE_OFFICER: { to: "/village-officer", label: "Review Queue" },
  REGISTRAR: { to: "/registrar", label: "Registrar Queue" },
};

function navLinkClasses(isActive: boolean) {
  // Both states keep full-opacity Apricot text (4.55:1 on Coffee, the
  // measured AA floor) — hierarchy comes from the background fill, not
  // from dimming the text, since any transparency here drops well below
  // AA (measured: apricot/85 → 3.78:1, apricot/70 → 3.10:1, both fail).
  return [
    "rounded-md px-3 py-1.5 text-sm font-medium text-apricot transition-colors",
    isActive ? "bg-coffee-hover" : "hover:bg-coffee-hover",
  ].join(" ");
}

function Emblem() {
  return (
    <svg viewBox="0 0 24 24" className="h-6 w-6 text-apricot" aria-hidden="true">
      <path
        d="M12 2.5l7.5 3.2v5.1c0 5-3.2 8.9-7.5 10.7-4.3-1.8-7.5-5.7-7.5-10.7V5.7L12 2.5z"
        fill="currentColor"
        opacity="0.15"
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

export function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  // The hero page has its own Log In / Register CTAs as the single clear
  // action — showing the same pair in the nav too just competes with them.
  // Every other logged-out page (including /login and /register
  // themselves) keeps the nav links unchanged.
  const isHeroPage = location.pathname === "/";

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
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-coffee-hover bg-coffee">
        <div className="mx-auto flex max-w-6xl items-center gap-6 px-6 py-3">
          <Link
            to={user ? roleHomePath(user.role) : "/"}
            className="flex items-center gap-2 font-serif text-lg font-semibold text-apricot"
          >
            <Emblem />
            BhoomiRakshak
          </Link>

          {user && (
            <nav className="flex items-center gap-1">
              <NavLink to={ROLE_NAV[user.role].to} className={({ isActive }) => navLinkClasses(isActive)}>
                {ROLE_NAV[user.role].label}
              </NavLink>
              <NavLink to="/land-records" className={({ isActive }) => navLinkClasses(isActive)}>
                Registry
              </NavLink>
              <NavLink to="/certificates" className={({ isActive }) => navLinkClasses(isActive)}>
                Certificates
              </NavLink>
              <NavLink to="/verify" className={({ isActive }) => navLinkClasses(isActive)}>
                Verify
              </NavLink>
            </nav>
          )}

          <div className="ml-auto flex items-center gap-4">
            {user ? (
              <>
                <div className="text-right leading-tight">
                  <div className="text-sm font-medium text-apricot">{user.name}</div>
                  <div className="text-xs font-medium uppercase tracking-wide text-apricot">
                    {ROLE_LABELS[user.role]}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleLogout}
                  className="rounded-md border border-apricot px-3 py-1.5 text-sm font-medium text-apricot hover:bg-coffee-hover"
                >
                  Log out
                </button>
              </>
            ) : (
              !isHeroPage && (
                <>
                  <Link
                    to="/login"
                    className="text-sm font-medium text-apricot underline underline-offset-2"
                  >
                    Log in
                  </Link>
                  <Link
                    to="/register"
                    className="rounded-md bg-apricot px-3 py-1.5 text-sm font-medium text-coffee hover:bg-apricot/90"
                  >
                    Register
                  </Link>
                </>
              )
            )}
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-6xl flex-1 px-6 py-8">
        <Outlet />
      </main>

      <footer className="border-t border-coffee-hover bg-coffee py-4 text-center text-xs text-apricot">
        BhoomiRakshak — PKI-based Secure Land Record &amp; Ownership Management System
      </footer>
    </div>
  );
}
