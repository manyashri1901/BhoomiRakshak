import { useState, type FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import axios from "axios";
import { useAuth } from "../context/AuthContext";
import { roleHomePath } from "../lib/roleHome";

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const user = await login(email, password);
      // Always the signed-in user's own role home — never a "return to
      // where you were" path from location.state. This app has no session
      // persistence (by design), and a different user can log in next;
      // trusting a stale ProtectedRoute-attached `state.from` here would
      // redirect them into whatever route the previous session left behind.
      navigate(roleHomePath(user.role), { replace: true });
    } catch (err) {
      if (axios.isAxiosError(err) && err.response) {
        setError(err.response.data?.error ?? "Login failed");
      } else {
        setError("Could not reach the server. Please try again.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="mx-auto max-w-sm">
      <div className="rounded-lg border border-border-subtle bg-surface px-8 py-10 shadow-sm">
        <h1 className="font-serif text-2xl font-semibold text-ink">Sign in</h1>
        <p className="mt-1 text-sm text-muted">
          Access your BhoomiRakshak land records account.
        </p>

        {(location.state as { justRegistered?: boolean } | null)?.justRegistered && (
          <p className="mt-4 rounded-md bg-valid-chip px-3 py-2 text-sm text-dark-cocoa">
            Account created. Sign in to continue.
          </p>
        )}

        <form onSubmit={handleSubmit} className="mt-6 flex flex-col gap-4">
          <label className="flex flex-col gap-1">
            <span className="text-sm font-medium text-ink">Email</span>
            <input
              type="email"
              required
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="rounded-md border border-border-subtle px-3 py-2 text-sm outline-none focus:border-camel focus:ring-1 focus:ring-camel"
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-sm font-medium text-ink">Password</span>
            <input
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="rounded-md border border-border-subtle px-3 py-2 text-sm outline-none focus:border-camel focus:ring-1 focus:ring-camel"
            />
          </label>

          {error && (
            <p className="rounded-md bg-danger-chip px-3 py-2 text-sm text-wax-seal">{error}</p>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="mt-2 rounded-md bg-coffee px-4 py-2 text-sm font-semibold text-apricot transition-colors hover:bg-coffee-hover disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <p className="mt-6 text-center text-sm text-muted">
          Don&rsquo;t have an account?{" "}
          <Link to="/register" className="font-medium text-ink underline">
            Register
          </Link>
        </p>
      </div>
    </div>
  );
}
