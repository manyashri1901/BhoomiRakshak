import { api } from "./client";
import type { Certificate, RevokedCertificateSummary } from "../types";

export function getCertificateByUserId(userId: string) {
  return api.get<Certificate>(`/certificates/${userId}`).then((r) => r.data);
}

export function getCRL() {
  return api.get<RevokedCertificateSummary[]>("/certificates/crl").then((r) => r.data);
}

export function revokeCertificate(certificateId: string, reason: string) {
  return api
    .post<RevokedCertificateSummary>(`/certificates/${certificateId}/revoke`, { reason })
    .then((r) => r.data);
}
