# ThreatLens Frontend — Security Operations Console

A calm, dense, professional SOC (Security Operations Center) dashboard built for the ThreatLens AI-powered threat detection and telemetry platform.

Built with **React 19 + TypeScript + Vite**, **Tailwind CSS v4**, **shadcn/ui**, **TanStack Query & Table**, **Recharts**, **Zod**, and **Lucide Icons**.

---

## Architecture & Features

- **Dense SOC Console Aesthetic**: Dark theme by default with light theme toggle. Subdued near-black slate backgrounds, 1px hairline borders, muted teal accents, and strictly isolated semantic severity indicators (`critical`, `high`, `medium`, `low`).
- **Typography & Metrics**: Tabular numbers for all metrics, IBM Plex Sans for UI surfaces, and JetBrains Mono for telemetry IPs, endpoints, payloads, rule signatures, and timestamps.
- **JWT & Role-Based Access Control**: Transparent JWT token workflow with automatic background token refresh via `/api/auth/refresh/` on 401s, in-memory access token, `sessionStorage` persistence, and role stratification (`admin`, `analyst`, `viewer`).
- **Telemetry & Event Ingestion**: Live paginated event stream with filters for source IP and endpoint, plus a slide-out Ingestion Sheet with interactive monospace JSON payload editor.
- **Hybrid Threat Detections**:
  - Filterable incident list with risk score breakdown.
  - **Detection Detail Centerpiece**: Risk calculation formula breakdown showing 50% Rule Engine signal + 50% ML Model confidence, deterministic severity floor notifications, raw payload inspector, and on-demand Groq LLM attack explanation (`openai/gpt-oss-120b`).
- **Alert Triage Queue**: Real-time status escalation (`open`, `investigating`, `resolved`) with TanStack Query optimistic updates and rollback on failure.
- **Asset Vulnerability Scans**: Queue target network/host scans and inspect lifecycle execution timestamps.
- **Executive Security Reports**: Aggregated telemetry statistics view, one-click Groq AI executive report generator, and printable/PDF-ready layout.
- **Global Command Menu**: `⌘K` / `Ctrl+K` command palette for instant keyboard-first navigation and rapid incident ingestion across all screens.

---

## Getting Started

### 1. Prerequisites
- Node.js (v18+) & npm
- ThreatLens Django backend running at `http://127.0.0.1:8000`

### 2. Environment Setup
Copy the template environment variables:
```bash
cp .env.example .env
```

Contents of `.env`:
```env
# Leave empty in development to use Vite's built-in reverse proxy (no CORS issues)
# Or specify your full backend URL: http://127.0.0.1:8000
VITE_API_URL=
```

### 3. Install Dependencies
```bash
npm install
```

### 4. Start Development Server
```bash
npm run dev
```
The application will launch at: **`http://localhost:5173`**

### 5. Production Build
```bash
npm run build
```
Generates production-optimized static assets in `/dist`.

---

## Testing Credentials

You can create an operator account on the register page (`/register`), or log in with any superuser/analyst created on the backend:

```bash
# In the backend directory:
python manage.py createsuperuser
```
Use those credentials to log into the ThreatLens console at `http://localhost:5173/login`.
