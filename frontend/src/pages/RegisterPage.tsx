import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";
import { useAuth } from "../context/AuthContext";
import { ROLE_LABELS } from "../lib/roleHome";
import type { Role } from "../types";

const ROLES: Role[] = ["LANDOWNER", "VILLAGE_OFFICER", "REGISTRAR"];

export function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("LANDOWNER");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await register({ name, email, password, role });
      navigate("/login", { state: { justRegistered: true } });
    } catch (err) {
      if (axios.isAxiosError(err) && err.response) {
        setError(err.response.data?.error ?? "Registration failed");
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
        <h1 className="font-serif text-2xl font-semibold text-ink">Create an account</h1>
        <p className="mt-1 text-sm text-muted">
          Registration issues you an RSA key pair and a CA-signed certificate.
        </p>

        <form onSubmit={handleSubmit} className="mt-6 flex flex-col gap-4">
          <label className="flex flex-col gap-1">
            <span className="text-sm font-medium text-ink">Full name</span>
            <input
              type="text"
              required
              autoComplete="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="rounded-md border border-border-subtle px-3 py-2 text-sm outline-none focus:border-camel focus:ring-1 focus:ring-camel"
            />
          </label>

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
              minLength={8}
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="rounded-md border border-border-subtle px-3 py-2 text-sm outline-none focus:border-camel focus:ring-1 focus:ring-camel"
            />
            <span className="text-xs text-muted">At least 8 characters.</span>
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-sm font-medium text-ink">Role</span>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as Role)}
              className="rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm outline-none focus:border-camel focus:ring-1 focus:ring-camel"
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABELS[r]}
                </option>
              ))}
            </select>
          </label>

          {error && (
            <p className="rounded-md bg-danger-chip px-3 py-2 text-sm text-wax-seal">{error}</p>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="mt-2 rounded-md bg-coffee px-4 py-2 text-sm font-semibold text-apricot transition-colors hover:bg-coffee-hover disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting ? "Creating account…" : "Register"}
          </button>
        </form>

        <p className="mt-6 text-center text-sm text-muted">
          Already registered?{" "}
          <Link to="/login" className="font-medium text-ink underline">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
}
