import { api } from "./client";
import type { Certificate } from "../types";

export function getCertificateByUserId(userId: string) {
  return api.get<Certificate>(`/certificates/${userId}`).then((r) => r.data);
}
