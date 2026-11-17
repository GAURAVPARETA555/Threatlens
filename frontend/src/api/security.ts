import api from "./client";
import type { PaginatedResponse } from "./client";
import type {
  SecurityEvent,
  DetectionResult,
  Alert,
  AlertStatus,
  Scan,
  ScanCreatePayload,
} from "./schemas";

/* ─── Events ─── */
export async function createEvent(payload: Record<string, unknown>) {
  const { data } = await api.post<SecurityEvent>("/api/events/", payload);
  return data;
}

export async function listEvents(params?: {
  source_ip?: string;
  endpoint?: string;
  page?: number;
  page_size?: number;
}) {
  const { data } = await api.get<PaginatedResponse<SecurityEvent>>(
    "/api/events/list/",
    { params },
  );
  return data;
}

/* ─── Detections ─── */
export async function analyzeDetection(eventId: number) {
  const { data } = await api.post<DetectionResult>(
    "/api/detections/analyze/",
    { event_id: eventId },
  );
  return data;
}

export async function listDetections(params?: {
  severity?: string;
  page?: number;
  page_size?: number;
}) {
  const { data } = await api.get<PaginatedResponse<DetectionResult>>(
    "/api/detections/",
    { params },
  );
  return data;
}

/* ─── Alerts ─── */
export async function listAlerts(params?: {
  severity?: string;
  status?: string;
  page?: number;
  page_size?: number;
}) {
  const { data } = await api.get<PaginatedResponse<Alert>>("/api/alerts/", {
    params,
  });
  return data;
}

export async function updateAlertStatus(id: number, status: AlertStatus) {
  const { data } = await api.patch<Alert>(`/api/alerts/${id}/`, { status });
  return data;
}

/* ─── Scans ─── */
export async function listScans(params?: {
  page?: number;
  page_size?: number;
}) {
  const { data } = await api.get<PaginatedResponse<Scan>>("/api/scans/", {
    params,
  });
  return data;
}

export async function createScan(payload: ScanCreatePayload) {
  const { data } = await api.post<Scan>("/api/scans/", payload);
  return data;
}

export async function getScan(id: number) {
  const { data } = await api.get<Scan>(`/api/scans/${id}/`);
  return data;
}
