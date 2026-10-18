import { useState, type FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import axios from "axios";
import { useAuth } from "../context/AuthContext";
import { roleHomePath } from "../lib/roleHome";
import { getErrorMessage } from "../lib/errorMessage";
import { Field, fieldInputClasses } from "../components/ui/Field";
import { Button } from "../components/ui/Button";
import { Banner } from "../components/ui/Banner";

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
        setError(getErrorMessage(err, "Login failed"));
      } else {
        setError("Could not reach the server. Please try again.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="mx-auto max-w-sm">
      <div className="rounded-xl border border-slate-200 bg-white px-8 py-10 shadow-sm">
        <h1 className="text-2xl font-semibold text-slate-900">Sign in</h1>
        <p className="mt-1 text-sm text-slate-600">Access your BhoomiRakshak land records account.</p>

        {(location.state as { justRegistered?: boolean } | null)?.justRegistered && (
          <div className="mt-4">
            <Banner variant="success">Account created. Sign in to continue.</Banner>
          </div>
        )}

        <form onSubmit={handleSubmit} className="mt-6 flex flex-col gap-4">
          <Field label="Email">
            <input
              type="email"
              required
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className={fieldInputClasses}
            />
          </Field>

          <Field label="Password">
            <input
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={fieldInputClasses}
            />
          </Field>

          {error && <Banner variant="danger">{error}</Banner>}

          <Button type="submit" loading={submitting} className="mt-2 w-full">
            {submitting ? "Signing in…" : "Sign in"}
          </Button>
        </form>

        <p className="mt-6 text-center text-sm text-slate-600">
          Don&rsquo;t have an account?{" "}
          <Link to="/register" className="font-medium text-navy underline">
            Register
          </Link>
        </p>
      </div>
    </div>
  );
}
