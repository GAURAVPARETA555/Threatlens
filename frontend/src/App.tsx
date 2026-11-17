import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AppLayout } from "@/components/layout/AppLayout";
import { ProtectedRoute } from "@/features/auth/ProtectedRoute";
import { LoginPage } from "@/features/auth/LoginPage";
import { RegisterPage } from "@/features/auth/RegisterPage";
import { OverviewPage } from "@/features/overview/OverviewPage";
import { EventsPage } from "@/features/events/EventsPage";
import { DetectionsListPage } from "@/features/detections/DetectionsListPage";
import { DetectionDetailPage } from "@/features/detections/DetectionDetailPage";
import { AlertsPage } from "@/features/alerts/AlertsPage";
import { ScansPage } from "@/features/scans/ScansPage";
import { ReportsPage } from "@/features/reports/ReportsPage";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public Auth Routes */}
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />

        {/* Protected Application Routes */}
        <Route element={<ProtectedRoute />}>
          <Route element={<AppLayout />}>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/events" element={<EventsPage />} />
            <Route path="/detections" element={<DetectionsListPage />} />
            <Route path="/detections/:id" element={<DetectionDetailPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/scans" element={<ScansPage />} />
            <Route path="/reports" element={<ReportsPage />} />
          </Route>
        </Route>

        {/* Catch-all redirect */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
