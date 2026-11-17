import { z } from "zod";

/* ─── Auth ─── */
export const loginSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});
export type LoginPayload = z.infer<typeof loginSchema>;

export const registerSchema = z.object({
  username: z.string().min(1, "Username is required"),
  email: z.string().email("Invalid email"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});
export type RegisterPayload = z.infer<typeof registerSchema>;

export const tokenResponseSchema = z.object({
  access: z.string(),
  refresh: z.string(),
});

export const userSchema = z.object({
  id: z.number(),
  username: z.string(),
  email: z.string(),
  role: z.enum(["admin", "analyst", "viewer"]),
});
export type User = z.infer<typeof userSchema>;

/* ─── Security Event ─── */
export const securityEventSchema = z.object({
  id: z.number(),
  timestamp: z.string(),
  source_ip: z.string(),
  endpoint: z.string(),
  raw_payload: z.record(z.string(), z.unknown()).default({}),
  request_rate: z.number(),
  failed_login_count: z.number(),
  special_char_count: z.number(),
});
export type SecurityEvent = z.infer<typeof securityEventSchema>;

export const eventCreateSchema = z.object({
  source_ip: z.string().min(1, "Source IP is required"),
  endpoint: z.string().min(1, "Endpoint is required"),
  request_rate: z.coerce.number().min(0),
  failed_login_count: z.coerce.number().int().min(0),
  special_char_count: z.coerce.number().int().min(0),
  raw_payload: z.string().optional(),
});
export type EventCreatePayload = z.infer<typeof eventCreateSchema>;

/* ─── Attack ─── */
export const attackSchema = z.object({
  id: z.number(),
  name: z.string(),
  category: z.string(),
  owasp_mapping: z.string(),
  mitre_mapping: z.string(),
  default_severity: z.enum(["low", "medium", "high", "critical"]),
});
export type Attack = z.infer<typeof attackSchema>;

/* ─── Detection Result ─── */
export const detectionResultSchema = z.object({
  id: z.number(),
  event: z.number(),
  attack: z.number().nullable(),
  rule_detected: z.boolean(),
  rule_confidence: z.number(),
  rule_evidence: z.string(),
  ml_prediction: z.string(),
  ml_confidence: z.number(),
  final_risk_score: z.number(),
  final_severity: z.enum(["low", "medium", "high", "critical"]),
  created_at: z.string(),
});
export type DetectionResult = z.infer<typeof detectionResultSchema>;

export const detectionAnalyzeSchema = z.object({
  event_id: z.coerce.number().int().min(1, "Event ID is required"),
});
export type DetectionAnalyzePayload = z.infer<typeof detectionAnalyzeSchema>;

/* ─── Alert ─── */
export const alertStatusValues = ["open", "investigating", "resolved"] as const;
export type AlertStatus = (typeof alertStatusValues)[number];

export const alertSchema = z.object({
  id: z.number(),
  detection: z.number(),
  status: z.enum(alertStatusValues),
  assigned_to: z.number().nullable(),
  created_at: z.string(),
  resolved_at: z.string().nullable(),
});
export type Alert = z.infer<typeof alertSchema>;

/* ─── Scan ─── */
export const scanStatusValues = [
  "pending",
  "running",
  "completed",
  "failed",
] as const;

export const scanSchema = z.object({
  id: z.number(),
  requested_by: z.number(),
  target: z.string(),
  status: z.enum(scanStatusValues),
  started_at: z.string().nullable(),
  completed_at: z.string().nullable(),
  created_at: z.string(),
});
export type Scan = z.infer<typeof scanSchema>;

export const scanCreateSchema = z.object({
  target: z.string().min(1, "Target is required"),
});
export type ScanCreatePayload = z.infer<typeof scanCreateSchema>;

/* ─── AI Analysis ─── */
export const aiAnalysisSchema = z.object({
  id: z.number(),
  detection_id: z.number(),
  explanation: z.string(),
  impact: z.string(),
  recommended_mitigation: z.string(),
  created_at: z.string(),
  updated_at: z.string(),
});
export type AIAnalysis = z.infer<typeof aiAnalysisSchema>;

/* ─── Report ─── */
export const reportSchema = z.object({
  id: z.number(),
  generated_by: z.number().nullable(),
  date_range_start: z.string().nullable(),
  date_range_end: z.string().nullable(),
  summary_json: z.record(z.string(), z.unknown()).default({}),
  created_at: z.string(),
});
export type Report = z.infer<typeof reportSchema>;

/* ─── Report Summary ─── */
export const severityDistributionSchema = z.object({
  critical: z.number(),
  high: z.number(),
  medium: z.number(),
  low: z.number(),
});

export const alertSummarySchema = z.object({
  open: z.number(),
  investigating: z.number(),
  resolved: z.number(),
});

export const reportSummarySchema = z.object({
  generated_at: z.string(),
  total_security_events: z.number(),
  total_detections: z.number(),
  rule_detected_count: z.number(),
  malicious_ml_predictions: z.number(),
  average_risk_score: z.number(),
  severity_distribution: severityDistributionSchema,
  alert_summary: alertSummarySchema,
  attack_distribution: z.array(
    z.object({
      attack__name: z.string().nullable(),
      count: z.number(),
    }),
  ),
});
export type ReportSummary = z.infer<typeof reportSummarySchema>;

export type Severity = "low" | "medium" | "high" | "critical";
