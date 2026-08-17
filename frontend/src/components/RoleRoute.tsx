import { Outlet } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import type { Role } from "../types";
import { NotAuthorized } from "../pages/NotAuthorized";

interface RoleRouteProps {
  allowed: Role[];
}

// Nest under ProtectedRoute, so `user` is guaranteed non-null here. Mirrors
// the backend's requireRole(...roles) — this is a UX convenience only, the
// real enforcement is server-side on every request.
export function RoleRoute({ allowed }: RoleRouteProps) {
  const { user } = useAuth();

  if (!user || !allowed.includes(user.role)) {
    return <NotAuthorized />;
  }

  return <Outlet />;
}
