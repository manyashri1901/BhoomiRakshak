// context/AuthContext.tsx
//
// Auth state lives only in React state (not localStorage) — per the MVP
// spec, a page refresh loses the session and the user re-logs in. The
// axios instance's token is kept in sync via setAuthToken() so every
// request automatically carries the current bearer token.

import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { api, setAuthToken } from "../api/client";
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

  const login = useCallback(async (email: string, password: string) => {
    const { data } = await api.post<{ token: string }>("/auth/login", { email, password });
    setAuthToken(data.token);

    const { userId, role } = decodeJwtPayload(data.token);
    // The JWT deliberately only carries {userId, role} (kept separate from
    // PKI identity) — fetch the display name separately for the nav bar.
    const { data: me } = await api.get<{ id: string; name: string; role: Role }>("/auth/me");

    const authUser: AuthUser = { userId, role, name: me.name };
    setUser(authUser);
    return authUser;
  }, []);

  const register = useCallback(async (input: RegisterInput) => {
    await api.post("/auth/register", input);
  }, []);

  const logout = useCallback(() => {
    setAuthToken(null);
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider
      value={{ user, isAuthenticated: user !== null, login, register, logout }}
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
