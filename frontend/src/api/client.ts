// api/client.ts
//
// Single axios instance shared by the whole app. The auth token lives in
// module scope (not React state) so the request interceptor always reads
// the current value without needing the instance to be recreated on every
// login/logout — AuthContext just calls setAuthToken() to keep this in sync.

import axios from "axios";
import { getErrorMessage } from "../lib/errorMessage";

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

// Rewrites every rejected request's own .message from Axios's generic
// "Request failed with status code ___" to the server's actual error text
// (getErrorMessage: response body's `error`, then `message`, then a
// plain-string body, then a generic fallback) — so any code that reads
// err.message directly, not just code that calls getErrorMessage itself,
// shows the real reason. err.response/err.response?.data are left
// untouched; only the Error's own .message string is replaced.
api.interceptors.response.use(undefined, (error) => {
  if (axios.isAxiosError(error)) {
    error.message = getErrorMessage(error);
  }
  return Promise.reject(error);
});
