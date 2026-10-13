import { Link } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { roleHomePath, ROLE_LABELS } from "../lib/roleHome";

export function NotAuthorized() {
  const { user } = useAuth();

  return (
    <div className="mx-auto flex max-w-lg flex-col items-center gap-4 rounded-xl border border-slate-200 bg-white px-8 py-12 text-center shadow-sm">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-red-100 text-red-600">
        <ShieldAlert className="h-6 w-6" aria-hidden="true" />
      </div>
      <h1 className="text-xl font-semibold text-slate-900">Not authorized</h1>
      <p className="text-sm text-slate-600">
        {user
          ? `Your account is registered as ${ROLE_LABELS[user.role]}. This section is restricted to a different role.`
          : "You do not have access to this section."}
      </p>
      {user && (
        <Link
          to={roleHomePath(user.role)}
          className="mt-2 rounded-lg bg-navy px-4 py-2 text-sm font-semibold text-white hover:bg-navy-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-navy"
        >
          Go to your dashboard
        </Link>
      )}
    </div>
  );
}
