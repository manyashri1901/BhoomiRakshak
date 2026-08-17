import { api } from "./client";
import type { Role, UserSummary } from "../types";

export function searchUsers(params: { role?: Role; q?: string } = {}) {
  return api.get<UserSummary[]>("/users", { params }).then((r) => r.data);
}
