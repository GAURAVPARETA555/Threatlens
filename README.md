# CyberSec Sentinel - AI-Powered Threat Detection & Incident Response Platform

An enterprise-grade cybersecurity backend platform built with Django REST Framework, featuring hybrid rule-based and machine-learning attack detection, dynamic risk scoring, alert management, and automated AI security report generation via Groq Cloud LLM integration.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [System Architecture](#system-architecture)
- [Backend Structure](#backend-structure)
- [Core Workflows](#core-workflows)
  - [Authentication Flow](#authentication-flow)
  - [Security Detection & Hybrid Risk Flow](#security-detection--hybrid-risk-flow)
  - [AI Analysis & Groq Integration](#ai-analysis--groq-integration)
  - [Report Generation Engine](#report-generation-engine)
- [API Reference](#api-reference)
  - [Authentication Endpoints](#1-authentication-endpoints)
  - [Security & Ingestion Endpoints](#2-security--ingestion-endpoints)
  - [AI & Intelligence Endpoints](#3-ai--intelligence-endpoints)
  - [Report Endpoints](#4-report-endpoints)
- [Installation & Team Setup](#installation--team-setup)
- [Environment Configuration](#environment-configuration)
- [Running the Services](#running-the-services)
- [API Testing Guide](#api-testing-guide)
- [Git & GitHub Safety Notes](#git--github-safety-notes)

---

## Project Overview

**CyberSec Sentinel** serves as a centralized Security Operations Center (SOC) intelligence hub. It ingests raw telemetry events (network requests, failed login attempts, anomalous character payloads), evaluates them through deterministic heuristics and ML prediction pipelines, computes composite risk scores, and orchestrates remediation workflows. In addition, it leverages high-throughput LLMs via Groq (`openai/gpt-oss-120b`) to produce instant threat explanations, mitigation playbooks, and executive-ready security reports.

---

## Key Features

- **JWT Authentication & Role-Based Access Control**: Secure token-based access with custom `User` models and role stratification (`admin`, `analyst`, `viewer`).
- **Telemetry Event Ingestion**: Capture and query endpoint request rates, failed authentication spikes, and suspicious character patterns.
- **Hybrid Threat Detection Engine**:
  - **Rule-Based Engine**: Matches known signature attributes, OWASP Top 10 vulnerabilities, and MITRE ATT&CK techniques.
  - **Machine Learning Integration**: Communicates with an external/mock ML classifier to predict malicious intent with confidence intervals.
  - **Dynamic Risk Engine**: Computes weighted scores (`0-100`) and categorizes incidents into `low`, `medium`, `high`, and `critical` severities.
- **Incident & Alert Management**: Auto-escalates `high` and `critical` detections into tracked alerts with full lifecycle status (`open`, `investigating`, `resolved`).
- **Security Scan Tracking**: Record target asset scans with automated timestamping and state transitions.
- **AI-Powered Incident Explanation**: On-demand deep-dive analysis powered by Groq LLM returning structured JSON with situational explanation, impact analysis, and remediation actions.
- **Automated SOC & Executive Reporting**: Generates aggregated security telemetry metrics alongside AI executive summaries.

---

## Technology Stack

| Layer | Technology |
| :--- | :--- |
| **Backend Framework** | Django 5.2.17 |
| **Web API Toolkit** | Django REST Framework (DRF) 3.18.1 |
| **Authentication** | SimpleJWT (JSON Web Tokens) 5.5.1 |
| **AI / LLM Provider** | Groq Cloud API (`openai/gpt-oss-120b`) |
| **Primary Database** | SQLite (Development) / PostgreSQL (Production-Ready) |
| **Database Driver** | Psycopg 3.3.5 |
| **HTTP Client** | Requests 2.34.2 |
| **Environment Management** | Python-Dotenv 1.2.3 |

---

## System Architecture

```
                       +-----------------------------------+
                       |      Client / Security Agent      |
                       +-----------------------------------+
                                         |
                                (REST API / JWT)
                                         v
+-------------------------------------------------------------------------------+
|                             Django Application                                |
|                                                                               |
|  +--------------------+   +------------------------------------------------+  |
|  |   accounts app     |   |                 security app                   |  |
|  |  - Custom User     |   |  - SecurityEvent ingestion                     |  |
|  |  - JWT Login/Reg   |   |  - Rule evaluation & Attack mapping            |  |
|  +--------------------+   |  - ML client call                              |  |
|                           |  - Risk scoring (Rule 50% + ML 50%)            |  |
|                           |  - Alert tracking (high / critical)            |  |
|                           +------------------------------------------------+  |
|                                                  |                            |
|                           +------------------------------------------------+  |
|                           |                 insights app                   |  |
|                           |  - AI incident explanation (Groq)              |  |
|                           |  - Metrics aggregation                         |  |
|                           |  - Executive report generation                 |  |
|                           +------------------------------------------------+  |
+-------------------------------------------------------------------------------+
         |                                |                            |
         v                                v                            v
+------------------+           +--------------------+       +--------------------+
|  SQLite / Postgre |           |   Mock ML Service  |       |   Groq Cloud API   |
|     Database     |           | (Port 8001/predict)|       | (gpt-oss-120b)     |
+------------------+           +--------------------+       +--------------------+
```

---

## Backend Structure

```
cyber-project/
├── .gitignore               # Root Git exclusion rules (secrets, venv, db)
├── README.md                # Project documentation and team onboarding guide
├── backend/
│   ├── manage.py            # Django CLI management entry point
│   ├── .env                 # LOCAL ONLY: Real secrets (ignored by Git)
│   ├── .env.example         # Template with placeholder variables for teams
│   ├── requirements.txt     # Python dependency specifications
│   ├── mock_ml.py           # Standalone mock ML microservice for local testing
│   ├── config/              # Core Django project configuration
│   │   ├── settings.py      # Environment-variable driven settings
│   │   ├── urls.py          # Root URL routing dispatcher
│   │   ├── asgi.py          # ASGI server entry point
│   │   └── wsgi.py          # WSGI server entry point
│   ├── accounts/            # User authentication and authorization
│   │   ├── models.py        # Custom User model with roles (admin, analyst, viewer)
│   │   ├── serializers.py   # User and registration serializers
│   │   ├── views.py         # Registration and account management views
│   │   └── urls.py          # /api/auth/ endpoints
│   ├── security/            # Ingestion, detection, risk calculation, alerts
│   │   ├── models.py        # Attack, SecurityEvent, DetectionResult, Alert, Scan
│   │   ├── risk_engine.py   # Composite scoring & severity classifier
│   │   ├── ml_client.py     # Microservice communication client
│   │   ├── serializers.py   # Serializers for events, detections, alerts, scans
│   │   ├── views.py         # Ingestion, analysis, alert update, and scan views
│   │   └── urls.py          # /api/ events, detections, alerts, scans endpoints
│   └── insights/            # LLM reasoning, metrics aggregation, reports
│       ├── models.py        # AIAnalysis and Report persistence models
│       ├── llm_client.py    # Groq OpenAI-compatible API client
│       ├── report_service.py# SQL aggregation service for security metrics
│       ├── serializers.py   # AI analysis and Report serializers
│       ├── views.py         # AI explanation and executive report views
│       └── urls.py          # /api/ai/ and /api/reports/ endpoints
```

### Module Responsibilities

1. **`accounts`**: Implements custom RBAC user identity, token distribution (SimpleJWT), and role permissions (`admin`, `analyst`, `viewer`).
2. **`security`**: Primary ingest pipe for telemetry. Orchestrates detection by joining rule indicators with ML confidence, computes composite risk scores, and manages alert status updates.
3. **`insights`**: Houses the AI reasoning layer. Interacts with the Groq Cloud completion API to explain attack mechanics, suggest tailored mitigations, and synthesize executive summaries.
4. **`config`**: Project root settings configured securely via environment variables with zero hardcoded credentials.

---

## Core Workflows

### Authentication Flow
1. Client registers via `POST /api/auth/register/` or logs in via `POST /api/auth/login/`.
2. SimpleJWT returns an `access` token (short-lived) and a `refresh` token.
3. Client includes the access token in subsequent requests via the HTTP header:
   ```http
   Authorization: Bearer <access_token>
   ```
4. Access tokens can be renewed using `POST /api/auth/refresh/`.

### Security Detection & Hybrid Risk Flow
1. Telemetry is submitted to `POST /api/detections/analyze/`.
2. The endpoint fetches the associated `SecurityEvent` record.
3. **Rule Detection**: Compares rule evidence and attack categorization against database attack signatures.
4. **ML Prediction**: Queries the configured `ML_SERVICE_URL` (`http://127.0.0.1:8001/predict/`) with telemetry features (`request_rate`, `failed_logins`, `special_characters`).
5. **Risk Engine**:
   - `Final Risk Score = ((Rule Confidence * 0.5) + (ML Confidence * 0.5)) * 100`
   - Classifies severity:
     - `Score >= 85`: **Critical**
     - `Score >= 65`: **High**
     - `Score >= 40`: **Medium**
     - `Score < 40`: **Low**
6. If severity is `high` or `critical`, an `Alert` is automatically created with status `open`.

### AI Analysis & Groq Integration
1. Analyst triggers `POST /api/ai/explain/<detection_id>/`.
2. Django gathers event attributes, OWASP and MITRE mappings, rule evidence, and ML predictions.
3. Django issues a structured JSON completion request to Groq using `openai/gpt-oss-120b`.
4. The response is parsed into `explanation`, `impact`, and `recommended_mitigation`, saved to the `AIAnalysis` model, and returned.

### Report Generation Engine
1. **Aggregated Metrics**: `GET /api/reports/summary/` queries database detections to compile statistics (total events, attack breakdowns, alert statuses, average risk scores).
2. **AI Executive Summary**: `POST /api/reports/ai-summary/` sends the aggregated metrics to Groq to generate executive findings, threat posture assessments, and strategic recommendations, persisting the output in `Report`.

---

## API Reference

### 1. Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/register/` | Register a new user account | None |
| `POST` | `/api/auth/login/` | Obtain JWT access and refresh token pair | None |
| `POST` | `/api/auth/refresh/` | Refresh expired access token | None |

#### Sample Registration Payload
```json
POST /api/auth/register/
{
  "username": "soc_analyst_1",
  "email": "analyst@enterprise.internal",
  "password": "StrongPassword123!",
  "role": "analyst"
}
```

---

### 2. Security & Ingestion Endpoints

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/events/` | Ingest raw security telemetry event | Bearer JWT |
| `GET` | `/api/events/list/` | List events (query params: `source_ip`, `endpoint`) | Bearer JWT |
| `POST` | `/api/detections/analyze/` | Run hybrid detection analysis on an event | Bearer JWT |
| `GET` | `/api/detections/` | List detections (query params: `severity`) | Bearer JWT |
| `GET` | `/api/alerts/` | List alerts (query params: `severity`, `status`) | Bearer JWT |
| `PUT / PATCH`| `/api/alerts/<id>/` | Update alert status (`open`, `investigating`, `resolved`)| Bearer JWT |
| `POST` | `/api/scans/` | Create security scan record | Bearer JWT |
| `GET` | `/api/scans/<id>/` | Retrieve scan details by ID | Bearer JWT |

#### Sample Ingestion Payload
```json
POST /api/events/
{
  "source_ip": "192.168.1.105",
  "endpoint": "/admin/login",
  "request_rate": 85.5,
  "failed_login_count": 14,
  "special_char_count": 6,
  "raw_payload": {"user_agent": "Mozilla/5.0", "param": "' OR '1'='1"}
}
```

#### Sample Detection Analyze Payload
```json
POST /api/detections/analyze/
{
  "event_id": 1,
  "attack_type": "SQL Injection",
  "rule_detected": true,
  "rule_confidence": 0.9,
  "evidence": "Suspicious SQL syntax patterns in request parameters"
}
```

---

### 3. AI & Intelligence Endpoints

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/ai/explain/<detection_id>/` | Request on-demand Groq AI explanation | Bearer JWT |
| `GET` | `/api/ai/explain/<detection_id>/` | Fetch cached AI explanation for a detection | Bearer JWT |

---

### 4. Report Endpoints

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/reports/summary/` | Compute telemetry metrics and save report | Bearer JWT |
| `POST` | `/api/reports/ai-summary/` | Generate and save AI executive security report | Bearer JWT |
| `GET` | `/api/reports/` | List all historical generated reports | Bearer JWT |

---

## Installation & Team Setup

### Prerequisites
- Python 3.10+ (or compatible virtual environment)
- Git
- Groq Cloud API key ([console.groq.com](https://console.groq.com))

### 1. Clone the Repository
```bash
git clone https://github.com/<your-org>/cyber-project.git
cd cyber-project
```

### 2. Set Up Virtual Environment

**On Windows (PowerShell):**
```powershell
python -m venv env
.\env\Scripts\Activate.ps1
```

**On Linux / macOS:**
```bash
python3 -m venv env
source env/bin/activate
```

### 3. Install Dependencies
```bash
cd backend
pip install -r requirements.txt
```

---

## Environment Configuration

Copy the template configuration file in `backend/`:

```bash
cp .env.example .env
```

Open `.env` in your editor and configure your secrets:

```env
# Django Settings
DJANGO_SECRET_KEY=generate_a_secure_random_key_here
DJANGO_DEBUG=True
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1

# Groq Cloud AI
GROQ_API_KEY=gsk_your_real_groq_api_key_here
GROQ_CHAT_MODEL=openai/gpt-oss-120b
LLM_API_URL=https://api.groq.com/openai/v1/chat/completions

# ML Service URL
ML_SERVICE_URL=http://127.0.0.1:8001/predict/
```

> [!IMPORTANT]
> Never commit `backend/.env` to Git. It is automatically ignored by `.gitignore`.

---

## Running the Services

### 1. Apply Database Migrations
```bash
python manage.py migrate
```

### 2. Create an Admin / Superuser
```bash
python manage.py createsuperuser
```

### 3. Start Mock ML Service (Optional for ML Testing)
In a separate terminal, start the standalone mock ML server:
```bash
python mock_ml.py
# Runs at http://127.0.0.1:8001/predict/
```

### 4. Start Django Development Server
```bash
python manage.py runserver 127.0.0.1:8000
```

---

## API Testing Guide

### 1. Obtain JWT Access Token
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "yourpassword"}'
```
*Save the returned `access` token.*

### 2. Ingest a Security Event
```bash
curl -X POST http://127.0.0.1:8000/api/events/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -d '{
    "source_ip": "10.0.0.5",
    "endpoint": "/api/v1/auth",
    "request_rate": 60.0,
    "failed_login_count": 8,
    "special_char_count": 3
  }'
```

### 3. Analyze Detection & Compute Risk
```bash
curl -X POST http://127.0.0.1:8000/api/detections/analyze/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -d '{
    "event_id": 1,
    "rule_detected": true,
    "rule_confidence": 0.85,
    "attack_type": "Brute Force",
    "evidence": "Repeated authorization failures"
  }'
```

### 4. Request Groq AI Explanation
```bash
curl -X POST http://127.0.0.1:8000/api/ai/explain/1/ \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

### 5. Generate AI Executive Security Report
```bash
curl -X POST http://127.0.0.1:8000/api/reports/ai-summary/ \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

---

## Git & GitHub Safety Notes

- **Secrets in `.env`**: Any API keys, secret keys, or database credentials must reside in `backend/.env`.
- **Pre-Commit Verification**: Run `git status` before committing to confirm that `backend/.env`, `db.sqlite3`, and `env/` are not staged.
- **Key Rotation**: If any key is ever accidentally committed to a public or private repository, consider it compromised immediately: revoke it from the provider dashboard and rotate to a new key.
