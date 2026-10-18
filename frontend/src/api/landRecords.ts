import { api } from "./client";
import type { AreaUnit, LandRecord, LandRecordHistory, LandRecordListItem, LandRecordStatus } from "../types";

export function listLandRecords() {
  return api.get<LandRecordListItem[]>("/land-records").then((r) => r.data);
}

export interface LandRecordSearchResult {
  id: string;
  surveyNumber: string;
  location: string;
  currentOwnerName: string;
  status: LandRecordStatus;
}

/** Exact-prefix survey-number search, not scoped to records the caller
 * owns — backs the "Claim as legal heir" flow (the heir needs to find a
 * record they don't currently own). */
export function searchLandRecords(q: string) {
  return api.get<LandRecordSearchResult[]>("/land-records/search", { params: { q } }).then((r) => r.data);
}

export function getLandRecordHistory(id: string) {
  return api.get<LandRecordHistory>(`/land-records/${id}/history`).then((r) => r.data);
}

export interface CreateLandRecordInput {
  surveyNumber: string;
  location: string;
  area: number;
  areaUnit: AreaUnit;
  currentOwnerId: string;
}

export function createLandRecord(input: CreateLandRecordInput) {
  return api.post<LandRecord>("/land-records", input).then((r) => r.data);
}
