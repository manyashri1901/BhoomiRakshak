import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { RoleRoute } from "./components/RoleRoute";
import { useAuth } from "./context/AuthContext";
import { roleHomePath } from "./lib/roleHome";
import { HomePage } from "./pages/HomePage";
import { LoginPage } from "./pages/LoginPage";
import { RegisterPage } from "./pages/RegisterPage";
import { LandownerDashboard } from "./pages/LandownerDashboard";
import { VillageOfficerDashboard } from "./pages/VillageOfficerDashboard";
import { RegistrarDashboard } from "./pages/RegistrarDashboard";
import { LandRecordsRegistry } from "./pages/LandRecordsRegistry";
import { LandRecordDetail } from "./pages/LandRecordDetail";
import { CertificateLookup } from "./pages/CertificateLookup";
import { VerifyPage } from "./pages/VerifyPage";

// "/" — the public landing page for signed-out visitors. Signed-in users
// land on their role's home instead; the page itself is never shown to them.
function RootRoute() {
  const { user } = useAuth();
  if (user) return <Navigate to={roleHomePath(user.role)} replace />;
  return <HomePage />;
}

// Unknown paths: signed-in users go to their role's home, everyone else
// goes to /login (not "/" — an unknown URL is more likely a broken/stale
// link than someone looking for the marketing page).
function UnknownRouteRedirect() {
  const { user } = useAuth();
  return <Navigate to={user ? roleHomePath(user.role) : "/login"} replace />;
}

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />

        <Route element={<ProtectedRoute />}>
          <Route path="/land-records" element={<LandRecordsRegistry />} />
          <Route path="/land-records/:id" element={<LandRecordDetail />} />
          <Route path="/certificates" element={<CertificateLookup />} />
          <Route path="/certificates/:userId" element={<CertificateLookup />} />
          <Route path="/verify" element={<VerifyPage />} />

          <Route element={<RoleRoute allowed={["LANDOWNER"]} />}>
            <Route path="/landowner" element={<LandownerDashboard />} />
          </Route>
          <Route element={<RoleRoute allowed={["VILLAGE_OFFICER"]} />}>
            <Route path="/village-officer" element={<VillageOfficerDashboard />} />
          </Route>
          <Route element={<RoleRoute allowed={["REGISTRAR"]} />}>
            <Route path="/registrar" element={<RegistrarDashboard />} />
          </Route>
        </Route>

        <Route path="/" element={<RootRoute />} />
        <Route path="*" element={<UnknownRouteRedirect />} />
      </Route>
    </Routes>
  );
}
