// context/AuthContext.tsx
//
// Auth state lives only in React state (not localStorage) — per the MVP
// spec, a page refresh loses the session and the user re-logs in. The
// axios instance's token is kept in sync via setAuthToken() so every
// request automatically carries the current bearer token.
//
// wrappedKey is the user's AES-256-GCM-wrapped private key, returned by
// the server at login (routes/auth.ts) — it is useless without the user's
// password (never stored here or anywhere client-side) to re-derive the
// unwrapping key, so holding it in React state is no more sensitive than
// holding the JWT. The server never sees the unwrapped key; see
// lib/clientCrypto.ts and lib/signAndSubmit.ts for where it's actually used.

import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { api, setAuthToken } from "../api/client";
import {
  generateKeyPair,
  exportPublicKeySpkiPem,
  fingerprintOfPem,
  wrapPrivateKey,
  signCanonicalString,
  type WrappedKeyBlob,
} from "../lib/clientCrypto";
import { canonicalStringify } from "../lib/canonicalize";
import type { AuthUser, Role } from "../types";

interface RegisterInput {
  name: string;
  email: string;
  password: string;
  role: Role;
}

interface AuthContextValue {
  user: AuthUser | null;
  isAuthenticated: boolean;
  wrappedKey: WrappedKeyBlob | null;
  login: (email: string, password: string) => Promise<AuthUser>;
  register: (input: RegisterInput) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

// The JWT is never verified client-side (that's meaningless without the
// server's secret) — decoding the payload here is purely for UI display
// and route-guard convenience. Every route it guards is re-checked by the
// backend's own requireAuth/requireRole on every request.
function decodeJwtPayload(token: string): { userId: string; role: Role } {
  const base64Url = token.split(".")[1];
  const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  const json = decodeURIComponent(
    atob(base64)
      .split("")
      .map((c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0"))
      .join(""),
  );
  return JSON.parse(json);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [wrappedKey, setWrappedKey] = useState<WrappedKeyBlob | null>(null);

  const login = useCallback(async (email: string, password: string) => {
    const { data } = await api.post<{ token: string; wrappedKey: WrappedKeyBlob | null }>(
      "/auth/login",
      { email, password },
    );
    setAuthToken(data.token);
    setWrappedKey(data.wrappedKey);

    const { userId, role } = decodeJwtPayload(data.token);
    // The JWT deliberately only carries {userId, role} (kept separate from
    // PKI identity) — fetch the display name separately for the nav bar.
    const { data: me } = await api.get<{ id: string; name: string; role: Role }>("/auth/me");

    const authUser: AuthUser = { userId, role, name: me.name };
    setUser(authUser);
    return authUser;
  }, []);

  const register = useCallback(async (input: RegisterInput) => {
    // Everything PKI-related happens here, in the browser, before anything
    // reaches the network: generate the key pair, prove possession of the
    // private key with a self-contained signed statement (no server round
    // trip needed first), then wrap the private key for storage and
    // discard the raw export. The server only ever receives the public
    // key, that proof, and the wrapped (encrypted) private key.
    const keyPair = await generateKeyPair();
    const publicKeyPem = await exportPublicKeySpkiPem(keyPair.publicKey);
    const fingerprint = await fingerprintOfPem(publicKeyPem);

    const email = input.email.trim().toLowerCase();
    const proofTimestamp = new Date().toISOString();
    const canonicalProof = canonicalStringify({ email, fingerprint, timestamp: proofTimestamp });
    const proofSignature = await signCanonicalString(keyPair.privateKey, canonicalProof);

    const wrapped = await wrapPrivateKey(keyPair.privateKey, input.password);

    await api.post("/auth/register", {
      name: input.name,
      email: input.email,
      password: input.password,
      role: input.role,
      publicKey: publicKeyPem,
      proofTimestamp,
      proofSignature,
      wrappedPrivateKey: wrapped.ciphertext,
      wrapSalt: wrapped.salt,
      wrapIv: wrapped.iv,
    });
  }, []);

  const logout = useCallback(() => {
    setAuthToken(null);
    setUser(null);
    setWrappedKey(null);
  }, []);

  return (
    <AuthContext.Provider
      value={{ user, isAuthenticated: user !== null, wrappedKey, login, register, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
