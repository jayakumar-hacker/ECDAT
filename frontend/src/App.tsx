import { BrowserRouter, Routes, Route } from "react-router-dom";
import AppLayout from "./layouts/AppLayout";
import ProtectedRoute from "./components/ProtectedRoute";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import ScanPage from "./pages/ScanPage";
import ScanHistoryPage from "./pages/ScanHistoryPage";
import InventoryPage from "./pages/InventoryPage";
import AssetDetailsPage from "./pages/AssetDetailsPage";
import CbomExplorerPage from "./pages/CbomExplorerPage";
import DependencyGraphPage from "./pages/DependencyGraphPage";
import QuantumRiskPage from "./pages/QuantumRiskPage";
import MoscaPage from "./pages/MoscaPage";
import RecommendationsPage from "./pages/RecommendationsPage";
import MigrationSimulatorPage from "./pages/MigrationSimulatorPage";
import CertificatesPage from "./pages/CertificatesPage";
import LibrariesPage from "./pages/LibrariesPage";
import ContainersPage from "./pages/ContainersPage";
import ReportsPage from "./pages/ReportsPage";
import AiAssistantPage from "./pages/AiAssistantPage";
import PostureDriftPage from "./pages/PostureDriftPage";
import HndlExposurePage from "./pages/HndlExposurePage";
import SettingsPage from "./pages/SettingsPage";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<AppLayout />}>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/scan" element={<ScanPage />} />
            <Route path="/scan-history" element={<ScanHistoryPage />} />
            <Route path="/inventory" element={<InventoryPage />} />
            <Route path="/assets/:id" element={<AssetDetailsPage />} />
            <Route path="/cbom" element={<CbomExplorerPage />} />
            <Route path="/dependency-graph" element={<DependencyGraphPage />} />
            <Route path="/quantum-risk" element={<QuantumRiskPage />} />
            <Route path="/mosca" element={<MoscaPage />} />
            <Route path="/recommendations" element={<RecommendationsPage />} />
            <Route path="/migration-simulator" element={<MigrationSimulatorPage />} />
            <Route path="/certificates" element={<CertificatesPage />} />
            <Route path="/libraries" element={<LibrariesPage />} />
            <Route path="/containers" element={<ContainersPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/ai-assistant" element={<AiAssistantPage />} />
            <Route path="/posture-drift" element={<PostureDriftPage />} />
            <Route path="/hndl-exposure" element={<HndlExposurePage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Route>
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
