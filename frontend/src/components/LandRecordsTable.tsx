import { Link } from "react-router-dom";
import { ArrowRightLeft } from "lucide-react";
import { formatAreaWithConversion } from "../lib/areaUnits";
import { LandRecordStatusBadge } from "./StatusBadge";
import { Button } from "./ui/Button";
import { SkeletonTableRows } from "./ui/Skeleton";
import type { LandRecordListItem } from "../types";

interface LandRecordsTableProps {
  records: LandRecordListItem[] | null;
  /** When set, the Actions column renders a "Transfer ownership" button
   * for each row where this id is the record's current owner and the
   * record is ACTIVE — never for anyone else's rows, matching exactly who
   * is allowed to start a transfer (routes/transactions.ts). Omit entirely
   * (e.g. on the Registry page, where the viewer is rarely a record's own
   * owner) and the Actions column is simply empty for every row that
   * doesn't qualify. */
  currentUserId?: string;
  onTransfer?: (record: LandRecordListItem) => void;
  /** Adds a "Current Owner" column between Area and Status — for the
   * Registry page, where the viewer isn't necessarily any record's owner
   * and benefits from seeing who is. Off on My Land, where every row is
   * already the caller's own. */
  showOwner?: boolean;
}

// Shared by LandownerDashboard ("My Land") and LandRecordsRegistry, so the
// two can never visually diverge. Plain block-flow table — no sticky
// header: the page itself scrolls (see Layout.tsx's <main>), and a sticky
// <thead> with no local scroll container was exactly what made the header
// detach from flow and float over the rows on a short table. The card
// simply grows to fit every row; overflow-x-auto + min-w-160 on the table
// (not the header) is what keeps a narrow window scrolling horizontally
// instead of overlapping, for however many rows there are.
export function LandRecordsTable({ records, currentUserId, onTransfer, showOwner = false }: LandRecordsTableProps) {
  const columnCount = showOwner ? 6 : 5;
  return (
    <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm">
      <table className="w-full min-w-160 border-collapse text-left text-sm">
        <thead>
          <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium uppercase tracking-wide text-slate-600">
            <th className="px-4 py-3">Survey No.</th>
            <th className="px-4 py-3">Location</th>
            <th className="px-4 py-3">Area</th>
            {showOwner && <th className="px-4 py-3">Current Owner</th>}
            <th className="px-4 py-3">Status</th>
            <th className="px-4 py-3">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {records === null && <SkeletonTableRows rows={3} columns={columnCount} />}
          {records?.map((r) => (
            <tr key={r.id} className="border-b border-slate-100 last:border-0 hover:bg-slate-50">
              <td className="px-4 py-3">
                <Link to={`/land-records/${r.id}`} className="font-medium text-navy underline">
                  {r.surveyNumber}
                </Link>
              </td>
              <td className="px-4 py-3 text-slate-700">{r.location}</td>
              <td className="px-4 py-3 text-slate-700">{formatAreaWithConversion(r.area, r.areaUnit)}</td>
              {showOwner && <td className="px-4 py-3 text-slate-700">{r.currentOwnerName}</td>}
              <td className="px-4 py-3">
                <LandRecordStatusBadge status={r.status} />
              </td>
              <td className="px-4 py-3 text-right">
                {onTransfer && currentUserId && r.currentOwnerId === currentUserId && r.status === "ACTIVE" && (
                  <Button
                    type="button"
                    variant="secondary"
                    icon={<ArrowRightLeft className="h-3.5 w-3.5" aria-hidden="true" />}
                    onClick={() => onTransfer(r)}
                  >
                    Transfer ownership
                  </Button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
