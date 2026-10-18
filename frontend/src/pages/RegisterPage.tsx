import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";
import { useAuth } from "../context/AuthContext";
import { ROLE_LABELS } from "../lib/roleHome";
import { getErrorMessage } from "../lib/errorMessage";
import { Field, fieldInputClasses } from "../components/ui/Field";
import { Button } from "../components/ui/Button";
import { Banner } from "../components/ui/Banner";
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
        setError(getErrorMessage(err, "Registration failed"));
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
        <h1 className="text-2xl font-semibold text-slate-900">Create an account</h1>
        <p className="mt-1 text-sm text-slate-600">
          Registration generates your signing key pair in this browser and issues a CA-signed
          certificate — your private key is encrypted with your password and never leaves your
          device unencrypted. There is no password reset: if you forget it, your key is
          unrecoverable and an admin must revoke and reissue your certificate.
        </p>

        <form onSubmit={handleSubmit} className="mt-6 flex flex-col gap-4">
          <Field label="Full name">
            <input
              type="text"
              required
              autoComplete="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className={fieldInputClasses}
            />
          </Field>

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

          <Field label="Password" helperText="At least 10 characters.">
            <input
              type="password"
              required
              minLength={10}
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={fieldInputClasses}
            />
          </Field>

          <Field label="Role">
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as Role)}
              className={fieldInputClasses}
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABELS[r]}
                </option>
              ))}
            </select>
          </Field>

          {error && <Banner variant="danger">{error}</Banner>}

          <Button type="submit" loading={submitting} className="mt-2 w-full">
            {submitting ? "Creating account…" : "Register"}
          </Button>
        </form>

        <p className="mt-6 text-center text-sm text-slate-600">
          Already registered?{" "}
          <Link to="/login" className="font-medium text-navy underline">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
}
