import { ShieldCheck } from "lucide-react";
import { CopyButton } from "./CopyButton";
import { ValidBadge } from "../ValidBadge";

export interface SecuritySignerRow {
  name: string;
  roleLabel: string;
  valid: boolean;
  /** Only set where the page's existing data fetch already includes it
   *  (see ReviewQueue.tsx) — never fetched specially for this card. */
  fingerprint?: string | null;
}

interface SecurityDetailsCardProps {
  signers: SecuritySignerRow[];
  documentHash: string;
}

function truncateMiddle(value: string, visible = 10) {
  if (value.length <= visible * 2 + 1) return value;
  return `${value.slice(0, visible)}…${value.slice(-visible)}`;
}

// Display-only summary of a transaction's cryptographic chain: every
// signer, their certificate fingerprint where already fetched, their
// signature status, and the document's recorded SHA-256 hash — all from
// data the page already has on hand, never a new request.
export function SecurityDetailsCard({ signers, documentHash }: SecurityDetailsCardProps) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex items-center gap-2">
        <ShieldCheck className="h-4.5 w-4.5 text-teal" aria-hidden="true" />
        <h4 className="text-sm font-semibold text-slate-900">Security details</h4>
      </div>

      <ul className="mt-3 flex flex-col divide-y divide-slate-100">
        {signers.map((signer, i) => (
          <li key={i} className="flex flex-wrap items-center justify-between gap-2 py-2.5">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-slate-900">{signer.name}</span>
                <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide text-slate-600">
                  {signer.roleLabel}
                </span>
              </div>
              {signer.fingerprint && (
                <div className="mt-0.5 flex items-center gap-1 font-mono text-xs text-slate-500">
                  <span title={signer.fingerprint}>{truncateMiddle(signer.fingerprint)}</span>
                  <CopyButton value={signer.fingerprint} label="Copy certificate fingerprint" />
                </div>
              )}
            </div>
            <ValidBadge valid={signer.valid} />
          </li>
        ))}
      </ul>

      <div className="mt-3 flex items-center justify-between gap-2 rounded-lg bg-slate-50 px-3 py-2">
        <div className="min-w-0">
          <div className="text-xs font-medium uppercase tracking-wide text-slate-500">Document SHA-256</div>
          <div className="truncate font-mono text-xs text-slate-700" title={documentHash}>
            {documentHash}
          </div>
        </div>
        <CopyButton value={documentHash} label="Copy document hash" />
      </div>
    </div>
  );
}
