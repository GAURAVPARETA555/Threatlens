Build the frontend for ThreatLens, a web-attack detection and security analytics
platform. The backend (Django REST, JWT) is finished and lives in /backend. Create
the frontend in /frontend. Do NOT guess API shapes: before building any screen, read
backend/security/serializers.py, views.py, models.py, backend/insights/serializers.py,
views.py, backend/accounts/serializers.py and backend/config/urls.py, and derive
exact field names, status values and response formats from them.

STACK
React + TypeScript + Vite, Tailwind, shadcn/ui components (install via CLI, do not
hand-roll what exists), React Router, TanStack Query, TanStack Table, Recharts,
Zod + react-hook-form, Lucide icons only (no emoji). Dev server on port 5173 against
http://127.0.0.1:8000 via VITE_API_URL.

DESIGN DIRECTION: calm, dense, professional SOC console (think Linear / Datadog /
Vercel dashboard), not a marketing page.
- Dark theme by default, light theme toggle. Define all tokens first as CSS
  variables: near-black slate background, 2 surface levels, 1 hairline border color,
  1 restrained accent (muted teal), semantic severity colors: critical = red,
  high = orange, medium = amber, low = slate-blue. Severity colors are used ONLY for
  severity. Use them as small badges/dots, never as big colored blocks.
- Fonts: IBM Plex Sans (UI), JetBrains Mono (IPs, endpoints, payloads, rule IDs,
  timestamps, numbers in tables). Tabular numbers for all metrics.
- Forbidden: purple/blue gradients, glassmorphism, glowing neon effects, emoji,
  centered hero sections, identical rounded-card grids, oversized shadows, decorative
  illustrations, placeholder/lorem copy, "Unleash/Empower/Seamless" style wording.
- Spacing on a 4/8/12/16/24/32 scale, 6-8px radii, 1px borders instead of shadows,
  compact table rows (36-40px), sticky table headers, keyboard-focusable everything.
- Every data view needs real loading skeletons, empty states with a useful next
  action, and error states showing the backend message. Handle 401 (silent refresh
  via /api/auth/refresh/, then redirect to login) and 403 (inline "insufficient
  permissions", not a crash).

LAYOUT: fixed left sidebar (Overview, Events, Detections, Alerts, Scans, Reports),
slim top bar with page title, global search (Cmd+K command menu), theme toggle, user
menu showing username and role badge (admin/analyst/viewer). Responsive down to
tablet; tables scroll horizontally inside their container.

AUTH: login and register pages (register sends username, email, password only;
new users are viewers). Keep the access token in memory and the refresh token in
sessionStorage; attach Bearer header through one axios/fetch wrapper. Protected
routes. Hide or disable mutating actions for the viewer role, but still handle 403.

PAGES
1. Overview: KPI strip (total events, detections, open alerts, critical count),
   severity distribution chart, detections-over-time chart, top attack types, top
   source IPs, recent alerts list. Use /api/reports/summary/ and list endpoints,
   whatever the real response contains.
2. Events: paginated table (source IP, endpoint, timestamp, analyzed status) with
   filters. "Ingest event" side sheet with a JSON payload editor (monospace) posting
   to /api/events/. Row action "Analyze" calls /api/detections/analyze/ and then
   navigates to the resulting detection.
3. Detections: paginated, filterable table (severity, attack type, date). Detection
   detail page is the centerpiece:
   - header: severity badge, risk score 0-100 as a segmented gauge or bar, attack type
   - "How the score was built": rule component (matched rule IDs, evidence string,
     severity weight) and ML component (prediction + confidence), shown with the
     formula Risk = (0.5 x rule + 0.5 x ML) x 100, and a note when the severity floor
     raised the final severity above the score-only band (85/65/40 thresholds)
   - raw event payload in a read-only monospace code block with horizontal scroll
   - telemetry features (request_rate, failed_logins, special_characters)
   - AI explanation panel: if one exists (GET /api/ai/explain/<id>/) render it, else a
     "Generate explanation" button (POST), with loading and error states and sections
     for explanation, impact, mitigation. Show a clear "AI-generated" label.
   - small footnote that the ML model is trained on synthetic telemetry.
4. Alerts: triage table with status filter and inline status change via PATCH
   /api/alerts/<id>/ using the exact status values from the model; optimistic update
   with rollback on error. Link each alert to its detection.
5. Scans: list/create/retrieve per /api/scans/ as the backend defines.
6. Reports: summary statistics view plus "Generate AI summary" (POST
   /api/reports/ai-summary/) and the saved reports list (GET /api/reports/). Render
   AI text as readable prose with a printable layout.

ENGINEERING
Typed API layer in /src/api with one file per resource, Zod schemas derived from the
backend serializers, query keys centralised, feature-based folder structure, shared
SeverityBadge / RiskGauge / DataTable / CodeBlock / EmptyState components, no
duplicated styles. Pagination reads `results`, `count`, `next`, `previous`;
page size via ?page_size=. Add a README with run instructions and .env.example.
Finish by running the build and fixing all type and lint errors.