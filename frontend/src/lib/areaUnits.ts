import type { AreaUnit } from "../types";

export const ACRES_PER_HECTARE = 2.47105;

export const AREA_UNIT_LABELS: Record<AreaUnit, string> = {
  HECTARE: "ha",
  ACRE: "acres",
};

// "2.5 ha (≈ 6.18 acres)" / "3 acres (≈ 1.21 ha)" — the stored value and
// unit first, then the converted equivalent for readers used to the other
// unit. Never used for anything computed (signing, validation) — display
// only.
export function formatAreaWithConversion(area: number, unit: AreaUnit): string {
  if (unit === "HECTARE") {
    const acres = area * ACRES_PER_HECTARE;
    return `${area} ha (≈ ${acres.toFixed(2)} acres)`;
  }
  const hectares = area / ACRES_PER_HECTARE;
  return `${area} acres (≈ ${hectares.toFixed(2)} ha)`;
}
