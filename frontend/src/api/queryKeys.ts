export const queryKeys = {
  events: {
    all: ["events"] as const,
    list: (params?: Record<string, unknown>) =>
      ["events", "list", params] as const,
  },
  detections: {
    all: ["detections"] as const,
    list: (params?: Record<string, unknown>) =>
      ["detections", "list", params] as const,
    detail: (id: number) => ["detections", "detail", id] as const,
  },
  alerts: {
    all: ["alerts"] as const,
    list: (params?: Record<string, unknown>) =>
      ["alerts", "list", params] as const,
  },
  scans: {
    all: ["scans"] as const,
    detail: (id: number) => ["scans", "detail", id] as const,
  },
  ai: {
    explanation: (detectionId: number) =>
      ["ai", "explanation", detectionId] as const,
  },
  reports: {
    all: ["reports"] as const,
    list: (params?: Record<string, unknown>) =>
      ["reports", "list", params] as const,
    summary: ["reports", "summary"] as const,
  },
} as const;
