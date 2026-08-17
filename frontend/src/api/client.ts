// api/client.ts
//
// Single axios instance shared by the whole app. The auth token lives in
// module scope (not React state) so the request interceptor always reads
// the current value without needing the instance to be recreated on every
// login/logout — AuthContext just calls setAuthToken() to keep this in sync.

import axios from "axios";

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? "http://localhost:4000/api",
});

let authToken: string | null = null;

export function setAuthToken(token: string | null) {
  authToken = token;
}

api.interceptors.request.use((config) => {
  if (authToken) {
    config.headers.set("Authorization", `Bearer ${authToken}`);
  }
  return config;
});
