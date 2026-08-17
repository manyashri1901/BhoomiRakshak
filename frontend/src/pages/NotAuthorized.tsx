import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { roleHomePath, ROLE_LABELS } from "../lib/roleHome";

export function NotAuthorized() {
  const { user } = useAuth();

  return (
    <div className="mx-auto flex max-w-lg flex-col items-center gap-4 rounded-lg border border-border-subtle bg-surface px-8 py-12 text-center shadow-sm">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-danger-chip text-wax-seal">
        <svg viewBox="0 0 24 24" fill="none" className="h-6 w-6" aria-hidden="true">
          <path
            d="M12 9v4m0 4h.01M10.29 3.86l-8.18 14.18A1.5 1.5 0 003.5 20h17a1.5 1.5 0 001.39-1.96l-8.18-14.18a1.5 1.5 0 00-2.62 0z"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </div>
      <h1 className="font-serif text-xl font-semibold text-ink">Not authorized</h1>
      <p className="text-sm text-muted">
        {user
          ? `Your account is registered as ${ROLE_LABELS[user.role]}. This section is restricted to a different role.`
          : "You do not have access to this section."}
      </p>
      {user && (
        <Link
          to={roleHomePath(user.role)}
          className="mt-2 rounded-md bg-coffee px-4 py-2 text-sm font-medium text-apricot hover:bg-coffee-hover"
        >
          Go to your dashboard
        </Link>
      )}
    </div>
  );
}
