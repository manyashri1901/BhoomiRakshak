import { useEffect, useState } from "react";
import { listLandRecords } from "../api/landRecords";
import { LandRecordsTable } from "../components/LandRecordsTable";
import { TransferOwnershipModal } from "../components/TransferOwnershipModal";
import { EmptyState, ErrorState } from "../components/States";
import { PageHeader } from "../components/ui/PageHeader";
import { Banner } from "../components/ui/Banner";
import { useAuth } from "../context/AuthContext";
import { getErrorMessage } from "../lib/errorMessage";
import type { LandRecordListItem } from "../types";

export function LandRecordsRegistry() {
  const { user } = useAuth();
  const [records, setRecords] = useState<LandRecordListItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [transferTarget, setTransferTarget] = useState<LandRecordListItem | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  function load() {
    listLandRecords()
      .then(setRecords)
      .catch((err) => {
        setError(getErrorMessage(err, "Failed to load land records"));
      });
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
      {successMessage && <Banner variant="success">{successMessage}</Banner>}
      {!error && records !== null && records.length === 0 && <EmptyState label="No land records to show yet." />}

      {!error && (records === null || records.length > 0) && (
        <LandRecordsTable records={records} currentUserId={user?.userId} onTransfer={setTransferTarget} showOwner />
      )}

      {transferTarget && (
        <TransferOwnershipModal
          landRecordId={transferTarget.id}
          surveyNumber={transferTarget.surveyNumber}
          onClose={() => setTransferTarget(null)}
          onTransferred={() => {
            setTransferTarget(null);
            setSuccessMessage("Transfer created and sent for Village Officer review.");
            load();
          }}
        />
      )}
    </div>
  );
}
