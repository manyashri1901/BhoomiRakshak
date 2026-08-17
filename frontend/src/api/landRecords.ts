import { api } from "./client";
import type { AreaUnit, LandRecord, LandRecordHistory, LandRecordListItem } from "../types";

export function listLandRecords() {
  return api.get<LandRecordListItem[]>("/land-records").then((r) => r.data);
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
