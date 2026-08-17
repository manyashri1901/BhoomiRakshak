import { useCallback, useEffect, useState, type FormEvent } from "react";
import axios from "axios";
import { createLandRecord } from "../api/landRecords";
import { listPendingRegistrar, reviewAsRegistrar } from "../api/transactions";
import { Card } from "../components/Card";
import { ErrorState } from "../components/States";
import { ReviewQueue } from "../components/ReviewQueue";
import { UserPicker } from "../components/UserPicker";
import type { AreaUnit, TransactionWithChain, UserSummary } from "../types";

export function RegistrarDashboard() {
  const [transactions, setTransactions] = useState<TransactionWithChain[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [surveyNumber, setSurveyNumber] = useState("");
  const [location, setLocation] = useState("");
  const [area, setArea] = useState("");
  const [areaUnit, setAreaUnit] = useState<AreaUnit>("HECTARE");
  const [owner, setOwner] = useState<UserSummary | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const load = useCallback(() => {
    listPendingRegistrar()
      .then(setTransactions)
      .catch((err) => {
        setLoadError(
          axios.isAxiosError(err)
            ? (err.response?.data?.error ?? "Failed to load review queue")
            : "Failed to load review queue",
        );
      });
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function handleCreateLandRecord(event: FormEvent) {
    event.preventDefault();
    setFormError(null);
    setSuccessMessage(null);

    const areaValue = Number(area);
    if (!surveyNumber.trim()) {
      setFormError("Survey number is required.");
      return;
    }
    if (!location.trim()) {
      setFormError("Location is required.");
      return;
    }
    if (!Number.isFinite(areaValue) || areaValue <= 0) {
      setFormError("Area must be a positive number.");
      return;
    }
    if (!owner) {
      setFormError("Select the landowner.");
      return;
    }

    setSubmitting(true);
    try {
      const record = await createLandRecord({
        surveyNumber: surveyNumber.trim(),
        location: location.trim(),
        area: areaValue,
        areaUnit,
        currentOwnerId: owner.id,
      });
      setSuccessMessage(`Land record ${record.surveyNumber} created.`);
      setSurveyNumber("");
      setLocation("");
      setArea("");
      setAreaUnit("HECTARE");
      setOwner(null);
    } catch (err) {
      setFormError(
        axios.isAxiosError(err)
          ? (err.response?.data?.error ?? "Failed to create land record")
          : "Failed to create land record",
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="font-serif text-2xl font-semibold text-ink">Registrar Queue</h1>
        <p className="mt-1 text-sm text-muted">Seed new land records and finalize approvals.</p>
      </div>

      <Card>
        <h2 className="font-serif text-lg font-semibold text-ink">Create Land Record</h2>
        <p className="mt-1 text-sm text-muted">Seeds a new parcel with status ACTIVE under a landowner.</p>

        <form onSubmit={handleCreateLandRecord} className="mt-4 flex flex-col gap-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <label className="flex flex-col gap-1">
              <span className="text-sm font-medium text-ink">Survey number</span>
              <input
                type="text"
                value={surveyNumber}
                onChange={(e) => setSurveyNumber(e.target.value)}
                className="rounded-md border border-border-subtle px-3 py-2 text-sm outline-none focus:border-camel focus:ring-1 focus:ring-camel"
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-sm font-medium text-ink">Area</span>
              <div className="flex gap-2">
                <input
                  type="number"
                  step="any"
                  min="0"
                  value={area}
                  onChange={(e) => setArea(e.target.value)}
                  className="w-full rounded-md border border-border-subtle px-3 py-2 text-sm outline-none focus:border-camel focus:ring-1 focus:ring-camel"
                />
                <select
                  value={areaUnit}
                  onChange={(e) => setAreaUnit(e.target.value as AreaUnit)}
                  className="rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm outline-none focus:border-camel focus:ring-1 focus:ring-camel"
                >
                  <option value="HECTARE">Hectare</option>
                  <option value="ACRE">Acre</option>
                </select>
              </div>
              <span className="text-xs text-muted" title="Indian land records are typically recorded in hectares (DILRMP standard) or acres — select the unit you're entering in.">
                Indian land records are typically recorded in hectares (DILRMP standard) or
                acres — select the unit you&rsquo;re entering in.
              </span>
            </label>
          </div>

          <label className="flex flex-col gap-1">
            <span className="text-sm font-medium text-ink">Location</span>
            <input
              type="text"
              value={location}
              onChange={(e) => setLocation(e.target.value)}
              className="rounded-md border border-border-subtle px-3 py-2 text-sm outline-none focus:border-camel focus:ring-1 focus:ring-camel"
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-sm font-medium text-ink">Owner</span>
            <UserPicker role="LANDOWNER" selected={owner} onSelect={setOwner} placeholder="Search landowners by name…" />
          </label>

          {formError && <ErrorState label={formError} />}
          {successMessage && (
            <p className="rounded-md bg-valid-chip px-3 py-2 text-sm text-dark-cocoa">{successMessage}</p>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="self-start rounded-md bg-coffee px-4 py-2 text-sm font-semibold text-apricot hover:bg-coffee-hover disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting ? "Creating…" : "Create Land Record"}
          </button>
        </form>
      </Card>

      <ReviewQueue
        title="Pending Registrar review"
        description="Both the landowner's and the Village Officer's signatures are verified live before any decision is recorded."
        transactions={transactions}
        loadError={loadError}
        emptyLabel="No pending transactions."
        onApprove={(id) => reviewAsRegistrar(id, "APPROVE")}
        onReject={(id, reason) => reviewAsRegistrar(id, "REJECT", reason)}
        onDecided={load}
      />
    </div>
  );
}
