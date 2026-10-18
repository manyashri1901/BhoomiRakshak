import axios from "axios";

// The one place that decides what error text a failed request shows. Used
// directly by call sites that want their own contextual fallback (e.g.
// "Failed to upload document"), and by api/client.ts's response
// interceptor, which rewrites every rejected AxiosError's own .message to
// this same result — so any code that reads err.message directly (e.g.
// PasswordPrompt.tsx's signing-dialog error display) gets the server's
// real message too, without needing to call this helper itself.
const GENERIC_FALLBACK = "Something went wrong. Please try again.";

export function getErrorMessage(err: unknown, fallback: string = GENERIC_FALLBACK): string {
  if (axios.isAxiosError(err)) {
    const data = err.response?.data;
    if (data && typeof data === "object") {
      const withFields = data as { error?: unknown; message?: unknown };
      if (typeof withFields.error === "string" && withFields.error.trim()) return withFields.error;
      if (typeof withFields.message === "string" && withFields.message.trim()) return withFields.message;
    } else if (typeof data === "string" && data.trim()) {
      return data;
    }
    return fallback;
  }
  if (err instanceof Error && err.message) return err.message;
  return fallback;
}
