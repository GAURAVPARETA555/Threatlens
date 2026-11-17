# ThreatLens — Project Implementation & Handover Summary

This document details the complete system state, architecture, completed tasks, credentials, and run instructions for developers and future LLM contexts.

---

## 1. System Overview

**ThreatLens** is an AI-powered cybersecurity detection and incident response platform. It ingests raw telemetry events, executes hybrid threat detection (deterministic heuristic rules + ML classification), dynamically calculates a composite risk score (0–100), auto-escalates high/critical threats to tracked alerts, and synthesizes executive/forensic reports via Groq Cloud LLM (`openai/gpt-oss-120b`).

- **Backend**: Django 5.2 + Django REST Framework + SimpleJWT + SQLite (dev) / PostgreSQL (prod).
- **ML Service**: Microservice running at `http://127.0.0.1:8001/predict/` (`mock_ml.py` or trained model `ml/serve.py`).
- **Frontend**: React 19 + TypeScript + Vite + Tailwind CSS v4 + shadcn/ui (Base UI) + TanStack Query & Table + Recharts + Zod.

---

## 2. Work Completed

### A. Frontend Architecture (`/frontend`)
Built strictly to specifications in `DESIGN.MD`:
1. **Design Tokens & Theme**:
   - Calm, dense SOC console layout (Linear / Datadog aesthetic).
   - Default dark theme (`#0b0f19` background) with light theme toggle.
   - 1px hairline borders, muted teal accents (`#0d9488` / `#2dd4bf`).
   - Strict semantic severity colors (`critical` = red, `high` = orange, `medium` = amber, `low` = slate-blue) restricted only to indicators/badges.
   - Typography: **IBM Plex Sans** (UI) and **JetBrains Mono** with tabular numerals for telemetry, payloads, and IPs.
2. **API & Authentication Layer**:
   - Typed API clients in `/src/api` (`auth.ts`, `security.ts`, `insights.ts`, `schemas.ts`, `queryKeys.ts`).
   - In-memory JWT access tokens, `sessionStorage` for refresh tokens, auto-refresh on 401s via `/api/auth/refresh/`.
   - Role-based permissions (`admin`, `analyst`, `viewer`): mutating actions are disabled for `viewer` with inline guidance.
3. **Core Shared Components**:
   - `SeverityBadge`: Status badge with pulsing dot.
   - `RiskGauge`: 10-segment responsive bar visualising scores 0–100 with dynamic severity classification.
   - `DataTable`: TanStack Table v8 with compact 36–40px rows, sticky headers, loading skeletons, error states, and pagination controls.
   - `CodeBlock`: Monospace read-only code block with horizontal scroll and 1-click clipboard copy.
   - `EmptyState`: Clean empty states with action triggers.
4. **All 6 Platform Pages**:
   - **Overview (`/`)**: KPI strip (events, detections, open alerts, critical count), Recharts severity donut, attack types bar chart, top origin IPs, recent alerts.
   - **Events (`/events`)**: Telemetry table with IP & endpoint filters, slide-out Ingestion Sheet with JSON editor, and row-level "Analyze" trigger.
   - **Detections (`/detections`)**: Paginated table filterable by severity.
   - **Detection Detail (`/detections/:id`)**: Centerpiece incident breakdown with segmented risk gauge, mathematical formula breakdown ($(\text{Rule} \times 0.5 + \text{ML} \times 0.5) \times 100$), deterministic severity floor warning, raw JSON payload viewer, extracted telemetry features, and on-demand Groq LLM forensics panel.
   - **Alerts (`/alerts`)**: Triage queue with inline status transitions (`open`, `investigating`, `resolved`) featuring **optimistic updates and rollback on error**.
   - **Scans (`/scans`)**: Host/network vulnerability scan tracking and creation modal (`POST /api/scans/`).
   - **Reports (`/reports`)**: Summary metrics, "Generate AI Executive Report" trigger, and printable/PDF export layout (`window.print()`).
5. **Global Command Menu**: `⌘K` / `Ctrl+K` command palette for rapid keyboard navigation across any page.

### B. Backend & Integration Fixes
1. **Virtual Environment**: Set up dedicated Python 3.11 virtual environment in `backend/env/`.
2. **Dependencies**: Installed all requirements from `backend/requirements.txt` plus `django-cors-headers`.
3. **CORS Configuration**: Enabled `django-cors-headers` middleware and origin allowances in `backend/config/settings.py` to prevent browser cross-origin blocks between port 5173 and 8000.
4. **JWT Claims Enhancement**: Customized SimpleJWT serializers to encode `username`, `email`, and `role` directly into token payloads and auth responses.
5. **API Compatibility**: Updated `ScanCreateView` in `backend/security/views.py` to `generics.ListCreateAPIView` to support both `GET` and `POST` on `/api/scans/`.
6. **Database & Migrations**: Applied all Django database migrations to `db.sqlite3`.
7. **Convenience Launchers**: Created root `.bat` scripts (`start_all.bat`, `run_backend.bat`, `run_frontend.bat`, `run_ml.bat`).

---

## 3. Test Credentials

| Username | Password | Role | Privileges |
| :--- | :--- | :--- | :--- |
| `admin` | `Password123!` | `admin` | Full operational and administrative access |
| `analyst1` | `Password123!` | `analyst` | Telemetry ingestion, detection analysis, scan launch, alert triage |
| `viewer1` | `Password123!` | `viewer` | Read-only observation across all telemetry and dashboards |

---

## 4. How to Run the Project

### Option A: 1-Click Launch (Recommended)
Double-click **`start_all.bat`** in the project root:
- Starts Django Backend on `http://127.0.0.1:8000`
- Starts Mock ML Service on `http://127.0.0.1:8001`
- Starts Frontend Vite Server on `http://localhost:5173`
- Automatically opens your default browser at `http://localhost:5173`

---

### Option B: Manual Multi-Terminal Launch

#### 1. Backend Server
```powershell
cd c:\Users\Akshat\Desktop\ThreatLens\Threatlens\backend
.\env\Scripts\activate
python manage.py runserver 127.0.0.1:8000
```

#### 2. Mock ML Service (Separate Terminal)
```powershell
cd c:\Users\Akshat\Desktop\ThreatLens\Threatlens\backend
.\env\Scripts\activate
python mock_ml.py
```

#### 3. Frontend Console (Separate Terminal)
```powershell
cd c:\Users\Akshat\Desktop\ThreatLens\Threatlens\frontend
npm run dev
```

---

## 5. Verification & Testing Checklist

1. **Authentication**:
   - Open `http://localhost:5173/login`.
   - Sign in as `admin` / `Password123!`. Verify redirection to Overview dashboard with `ADMIN` badge in top right.
2. **Ingest Event**:
   - Go to `/events` ➔ Click "Ingest Event".
   - Keep sample payload and submit. Verify event appears in the stream.
3. **Run Analysis**:
   - Click "Analyze" on the event.
   - Verify redirection to `/detections/:id`.
   - Check the 0–100 Segmented Risk Gauge and Rule/ML mathematical breakdown.
4. **Alerts Triage**:
   - Go to `/alerts`. Change an alert from `OPEN` to `INVESTIGATING` or `RESOLVED` in the dropdown. Verify optimistic update.
5. **Asset Scans**:
   - Go to `/scans`. Click "Launch Scan", provide a target IP/domain, submit, and inspect details.
6. **Reports**:
   - Go to `/reports`. Review telemetry stats, click "Generate AI Executive Report" (requires `GROQ_API_KEY` in `backend/.env`), or click "Print / Export PDF".

---

## 6. Key Configuration Files Reference

- **Backend Settings**: `backend/config/settings.py`
- **Backend Secrets**: `backend/.env` (Configures `DJANGO_SECRET_KEY`, `GROQ_API_KEY`, `ML_SERVICE_URL`)
- **Frontend Environment**: `frontend/.env` (`VITE_API_URL=`)
- **Vite Proxy Config**: `frontend/vite.config.ts` (proxies `/api` to `http://127.0.0.1:8000`)
- **Frontend Routes**: `frontend/src/App.tsx`
