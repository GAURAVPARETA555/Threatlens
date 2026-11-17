import api from "./client";
import type { AIAnalysis, Report } from "./schemas";
import type { PaginatedResponse } from "./client";

/* ─── AI Analysis ─── */
export async function generateAIExplanation(detectionId: number) {
  const { data } = await api.post<AIAnalysis>(
    `/api/ai/explain/${detectionId}/`,
  );
  return data;
}

export async function getAIExplanation(detectionId: number) {
  const { data } = await api.get<AIAnalysis>(
    `/api/ai/explain/${detectionId}/`,
  );
  return data;
}

/* ─── Reports ─── */
export async function getReportSummary() {
  const { data } = await api.get<Report>("/api/reports/summary/");
  return data;
}

export async function generateAIReport() {
  const { data } = await api.post<Report>("/api/reports/ai-summary/");
  return data;
}

export async function listReports(params?: {
  page?: number;
  page_size?: number;
}) {
  const { data } = await api.get<PaginatedResponse<Report>>("/api/reports/", {
    params,
  });
  return data;
}
