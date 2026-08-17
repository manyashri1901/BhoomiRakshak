import { Navigate, Outlet } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

// Layout route: renders its nested routes only when logged in, otherwise
// bounces to /login. No `state.from` "return to where you were" — this app
// has no session persistence and a different user may log in next, so
// redirecting back into a route the previous session left behind isn't safe.
export function ProtectedRoute() {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}
