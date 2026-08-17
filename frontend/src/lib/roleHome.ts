import type { Role } from "../types";

// Where each role lands after login / "go back home".
export function roleHomePath(role: Role): string {
  switch (role) {
    case "LANDOWNER":
      return "/landowner";
    case "VILLAGE_OFFICER":
      return "/village-officer";
    case "REGISTRAR":
      return "/registrar";
  }
}

export const ROLE_LABELS: Record<Role, string> = {
  LANDOWNER: "Landowner",
  VILLAGE_OFFICER: "Village Officer",
  REGISTRAR: "Registrar",
};
