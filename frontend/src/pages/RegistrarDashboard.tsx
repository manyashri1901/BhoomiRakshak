import { useCallback, useEffect, useState, type FormEvent } from "react";
import axios from "axios";
import { ClipboardList, Plus } from "lucide-react";
import { createLandRecord } from "../api/landRecords";
import {
  listPendingRegistrar,
  prepareRegistrarReview,
  submitRegistrarReview,
  rejectRegistrarReview,
} from "../api/transactions";
import { Card } from "../components/Card";
import { ReviewQueue } from "../components/ReviewQueue";
import { UserPicker } from "../components/UserPicker";
import { PageHeader } from "../components/ui/PageHeader";
import { StatCard } from "../components/ui/StatCard";
import { Button } from "../components/ui/Button";
import { Banner } from "../components/ui/Banner";
import { Field, fieldInputClasses } from "../components/ui/Field";
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
      <PageHeader title="Registrar Queue" subtitle="Seed new land records and finalize approvals." />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard label="Pending your approval" value={transactions?.length ?? 0} icon={ClipboardList} tone="warning" />
      </div>

      <Card>
        <h2 className="text-lg font-semibold text-slate-900">Create Land Record</h2>
        <p className="mt-1 text-sm text-slate-600">Seeds a new parcel with status ACTIVE under a landowner.</p>

        <form onSubmit={handleCreateLandRecord} className="mt-4 flex flex-col gap-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Field label="Survey number">
              <input
                type="text"
                value={surveyNumber}
                onChange={(e) => setSurveyNumber(e.target.value)}
                className={fieldInputClasses}
              />
            </Field>
            <Field
              label="Area"
              helperText="Indian land records are typically recorded in hectares (DILRMP standard) or acres — select the unit you're entering in."
            >
              <div className="flex gap-2">
                <input
                  type="number"
                  step="any"
                  min="0"
                  value={area}
                  onChange={(e) => setArea(e.target.value)}
                  className={`${fieldInputClasses} w-full`}
                />
                <select
                  value={areaUnit}
                  onChange={(e) => setAreaUnit(e.target.value as AreaUnit)}
                  className={fieldInputClasses}
                >
                  <option value="HECTARE">Hectare</option>
                  <option value="ACRE">Acre</option>
                </select>
              </div>
            </Field>
          </div>

          <Field label="Location">
            <input
              type="text"
              value={location}
              onChange={(e) => setLocation(e.target.value)}
              className={fieldInputClasses}
            />
          </Field>

          <Field label="Owner">
            <UserPicker role="LANDOWNER" selected={owner} onSelect={setOwner} placeholder="Search landowners by name…" />
          </Field>

          {formError && <Banner variant="danger">{formError}</Banner>}
          {successMessage && <Banner variant="success">{successMessage}</Banner>}

          <Button type="submit" loading={submitting} icon={<Plus className="h-4 w-4" aria-hidden="true" />} className="self-start">
            {submitting ? "Creating…" : "Create Land Record"}
          </Button>
        </form>
      </Card>

      <ReviewQueue
        title="Pending Registrar review"
        description="Both the landowner's and the Village Officer's signatures are verified live before any decision is recorded."
        transactions={transactions}
        loadError={loadError}
        emptyLabel="No pending transactions."
        prepareApprove={prepareRegistrarReview}
        submitApprove={submitRegistrarReview}
        onReject={rejectRegistrarReview}
        onDecided={load}
      />
    </div>
  );
}
