import { api } from "./client";
import type { CertificateEnvelope, CAInfo, SignedCRL } from "../lib/certificateVerify";
import type { Certificate, RevokedCertificateSummary, Role } from "../types";

export function getCertificateByUserId(userId: string) {
  return api.get<Certificate>(`/certificates/${userId}`).then((r) => r.data);
}

/** The caller's own certificate serial — nothing else. Backs the
 * Certificate Lookup page's "My certificate" shortcut. */
export function getMyCertificateSerial() {
  return api.get<{ serialNumber: string }>("/certificates/me").then((r) => r.data.serialNumber);
}

export function getCRL() {
  return api.get<RevokedCertificateSummary[]>("/certificates/crl").then((r) => r.data);
}

export function revokeCertificate(certificateId: string, reason: string) {
  return api
    .post<RevokedCertificateSummary>(`/certificates/${certificateId}/revoke`, { reason })
    .then((r) => r.data);
}

// --- Certificate Lookup rework: client-side-verifiable X.509 endpoints --

export function getCAInfo() {
  return api.get<CAInfo>("/certificates/ca").then((r) => r.data);
}

export function getSignedCRL() {
  return api.get<SignedCRL>("/certificates/crl/signed").then((r) => r.data);
}

/** Exact lookup by the certificate's real X.509 serial number — any
 * authenticated user. Returns the raw certificate PEM (plus the issuing
 * CA's own PEM, so the browser can verify the chain in one round trip);
 * the caller verifies it client-side (lib/certificateVerify.ts), never
 * trusting a server-computed verdict because there isn't one in this
 * response. */
export function getCertificateBySerial(serial: string) {
  return api.get<CertificateEnvelope>(`/certificates/serial/${serial}`).then((r) => r.data);
}

export interface CertificateSearchResult {
  serial: string;
  name: string;
  role: Role;
}

export interface CertificateSearchResponse {
  results: CertificateSearchResult[];
  nextCursor: string | null;
}

/** Name search — only ever reachable in the UI for VILLAGE_OFFICER/
 * REGISTRAR/ADMIN (the server enforces this independently; see
 * routes/certificates.ts). Minimum 3-character query, server-side. */
export function searchCertificates(params: { q: string; cursor?: string | null }) {
  return api
    .get<CertificateSearchResponse>("/certificates/search", { params })
    .then((r) => r.data);
}
