import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import axios from "axios";
import { listLandRecords } from "../api/landRecords";
import { formatAreaWithConversion } from "../lib/areaUnits";
import { LandRecordStatusBadge } from "../components/StatusBadge";
import { EmptyState, ErrorState } from "../components/States";
import { PageHeader } from "../components/ui/PageHeader";
import { SkeletonTableRows } from "../components/ui/Skeleton";
import { useAuth } from "../context/AuthContext";
import type { LandRecordListItem } from "../types";

export function LandRecordsRegistry() {
  const { user } = useAuth();
  const [records, setRecords] = useState<LandRecordListItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    listLandRecords()
      .then((data) => {
        if (!cancelled) setRecords(data);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(axios.isAxiosError(err) ? (err.response?.data?.error ?? "Failed to load land records") : "Failed to load land records");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Land Records Registry"
        subtitle={
          user?.role === "LANDOWNER"
            ? "Land parcels currently registered under your name."
            : "All land parcels registered in the system."
        }
      />

      {error && <ErrorState label={error} />}
      {!error && records !== null && records.length === 0 && <EmptyState label="No land records found." />}

      {!error && (records === null || records.length > 0) && (
        <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm">
          <table className="w-full min-w-160 border-collapse text-left text-sm">
            <thead className="sticky top-16 z-10">
              <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium uppercase tracking-wide text-slate-600">
                <th className="px-4 py-3">Survey No.</th>
                <th className="px-4 py-3">Location</th>
                <th className="px-4 py-3">Area</th>
                <th className="px-4 py-3">Current Owner</th>
                <th className="px-4 py-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {records === null && <SkeletonTableRows rows={4} columns={5} />}
              {records?.map((record) => (
                <tr key={record.id} className="border-b border-slate-100 last:border-0 hover:bg-slate-50">
                  <td className="px-4 py-3">
                    <Link to={`/land-records/${record.id}`} className="font-medium text-navy underline">
                      {record.surveyNumber}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-slate-700">{record.location}</td>
                  <td className="px-4 py-3 text-slate-700">
                    {formatAreaWithConversion(record.area, record.areaUnit)}
                  </td>
                  <td className="px-4 py-3 text-slate-700">{record.currentOwnerName}</td>
                  <td className="px-4 py-3">
                    <LandRecordStatusBadge status={record.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
