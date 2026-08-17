import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import axios from "axios";
import { listLandRecords } from "../api/landRecords";
import { formatAreaWithConversion } from "../lib/areaUnits";
import { LandRecordStatusBadge } from "../components/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
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
      <div>
        <h1 className="font-serif text-2xl font-semibold text-ink">Land Records Registry</h1>
        <p className="mt-1 text-sm text-muted">
          {user?.role === "LANDOWNER"
            ? "Land parcels currently registered under your name."
            : "All land parcels registered in the system."}
        </p>
      </div>

      {error && <ErrorState label={error} />}
      {!error && records === null && <LoadingState label="Loading land records…" />}
      {!error && records !== null && records.length === 0 && (
        <EmptyState label="No land records found." />
      )}

      {!error && records !== null && records.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-border-subtle bg-surface shadow-sm">
          <table className="w-full min-w-160 border-collapse text-left text-sm">
            <thead>
              <tr className="border-b border-border-subtle bg-neutral-chip text-xs font-medium uppercase tracking-wide text-ink">
                <th className="px-4 py-3">Survey No.</th>
                <th className="px-4 py-3">Location</th>
                <th className="px-4 py-3">Area</th>
                <th className="px-4 py-3">Current Owner</th>
                <th className="px-4 py-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {records.map((record) => (
                <tr key={record.id} className="border-b border-border-subtle last:border-0 hover:bg-neutral-chip">
                  <td className="px-4 py-3">
                    <Link
                      to={`/land-records/${record.id}`}
                      className="font-medium text-ink underline"
                    >
                      {record.surveyNumber}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-ink">{record.location}</td>
                  <td className="px-4 py-3 text-ink">
                    {formatAreaWithConversion(record.area, record.areaUnit)}
                  </td>
                  <td className="px-4 py-3 text-ink">{record.currentOwnerName}</td>
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
