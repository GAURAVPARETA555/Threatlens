# ThreatLens — CyberSecurity Detection Engineering Module

**AI-Powered Web Attack Detection & Security Analytics Platform**  
*Responsibility: Member 4 — Cybersecurity Detection Engineer*

---

## 1. Overview

The `CyberSecurity` module is the defensive detection core of the **ThreatLens** platform. It provides deterministic, high-throughput, in-process security analysis of incoming web application traffic, identifying attack payloads, behavioral anomalies, and security misconfigurations across 10 specialized detection domains.

### Key Capabilities
- **Zero External Dependencies:** Built entirely with the Python Standard Library (Python $\ge$ 3.10).
- **Sub-Millisecond Evaluation:** Average execution time $\approx 0.08\text{ ms}$ (80 microseconds) per event.
- **Robust Exception Isolation:** Defensive try-except boundary around all detectors prevents crashes.
- **Zero False-Certainty Confidence:** Strictly distinguishes rule heuristics from calibrated statistical probabilities.
- **Backend-Ready Integration Adapter:** Directly emits payloads validated against Member 1's Django REST Framework `DetectionAnalyzeSerializer`.
- **100% Passing Automated Tests:** 131 comprehensive unit and regression tests covering true positives, true negatives, edge cases, and historical defect fixes.

---

## 2. Architecture & Data Flow

```
                      ┌────────────────────────────────────────┐
                      │    HTTP Traffic / Reverse Proxy Logs   │
                      └──────────────────┬─────────────────────┘
                                         │
                                         ▼
                      ┌────────────────────────────────────────┐
                      │  Member 1: Django Backend REST API     │
                      │  (Ingests event -> SecurityEvent model)│
                      └──────────────────┬─────────────────────┘
                                         │ Event Dict {"id": 1, ...}
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ ThreatLens CyberSecurity Module (Member 4)                                             │
│                                                                                        │
│   ┌────────────────────────────────────────────────────────────────────────────────┐   │
│   │ Integration Adapter: evaluate_for_backend(event)                               │   │
│   │ - Validates event_id as positive integer                                       │   │
│   │ - Formats evidence into DRF CharField text                                     │   │
│   │ - Deterministically selects primary attack type via priority table             │   │
│   │ - Normalizes severity to backend lowercase choices                             │   │
│   └───────────────────────────────────┬────────────────────────────────────────────┘   │
│                                       │ Calls analyze_event()                          │
│                                       ▼                                                │
│   ┌────────────────────────────────────────────────────────────────────────────────┐   │
│   │ Central Detection Engine: Detection/engine.py                                  │   │
│   │ (Parallel module execution, exception isolation, deterministic aggregation)    │   │
│   └──────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┬───────┘   │
│          │          │          │          │          │          │          │           │
│          ▼          ▼          ▼          ▼          ▼          ▼          ▼           │
│       ┌──────┐   ┌──────┐   ┌──────┐   ┌──────┐   ┌──────┐   ┌──────┐   ┌──────┐       │
│       │ SQLi │   │ XSS  │   │ CMDi │   │ SSRF │   │PTrav │   │Brute │   │ ...  │       │
│       └──────┘   └──────┘   └──────┘   └──────┘   └──────┘   └──────┘   └──────┘       │
└───────────────────────────────────────┬────────────────────────────────────────────────┘
                                        │ Returns Validated Payload
                                        ▼
                      ┌────────────────────────────────────────┐
                      │  Member 1: Risk Engine & Alert Storage │
                      │  - Calculates risk: (Rule + ML) * 50   │
                      │  - Persists Alert if Score >= 65       │
                      │  - Serves React Dashboard (Member 2)   │
                      └────────────────────────────────────────┘
```

---

## 3. Directory Layout

```
CyberSecurity/
├── Detection/                      # Core detection engine & 10 rule modules
│   ├── __init__.py
│   ├── engine.py                  # Central coordinator & aggregation engine
│   ├── sqli.py                    # SQL Injection (SQLI-001 - SQLI-004)
│   ├── xss.py                     # Cross-Site Scripting (XSS-001 - XSS-003)
│   ├── brute_force.py             # Authentication Brute Force (BRUTE-001)
│   ├── command_injection.py       # OS Command Injection (CMDI-001 - CMDI-003)
│   ├── path_traversal.py          # Directory Path Traversal (PTRAV-001 - PTRAV-003)
│   ├── ssrf.py                    # Server-Side Request Forgery (SSRF-001 - SSRF-003)
│   ├── idor.py                    # Broken Access Control / IDOR (IDOR-001 - IDOR-002)
│   ├── session_security.py        # Session Hijacking & Fixation (SESSION-001 - SESSION-002)
│   ├── api_security.py            # API Gateway Abuse (API-001 - API-003)
│   └── security_misconfiguration.py# Response Headers & Body Leaks (MISCONFIG-001 - 006)
├── Integration/                   # Backend adapter layer for Member 1 Django
│   ├── __init__.py                # Public interface (evaluate_for_backend, CyberSecurityAdapter)
│   ├── adapter.py                 # Contract transformation & validation adapter
│   ├── exceptions.py              # Custom exceptions (EventValidationError, etc.)
│   ├── schemas.py                 # Canonical schemas & priority mappings
│   └── serializers.py             # Evidence, severity, & attack type formatters
├── Tests/                         # Automated unit & regression test suite (131 tests)
│   ├── Test_api_security.py
│   ├── Test_brute_force.py
│   ├── Test_command_injection.py
│   ├── Test_engine.py
│   ├── Test_idor.py
│   ├── Test_integration_adapter.py
│   ├── Test_path_traversal.py
│   ├── Test_security_misconfiguration.py
│   ├── Test_session_security.py
│   ├── Test_sqli.py
│   ├── Test_ssrf.py
│   └── Test_xss.py
├── Docs/                          # Complete technical & architectural documentation
│   ├── README.md                  # Documentation navigation index
│   ├── attack_taxonomy.md         # OWASP, CWE, and MITRE ATT&CK mappings
│   ├── detection_rules.md         # Comprehensive rule catalog (all 30 rules)
│   ├── security_event_schema.md   # Input event envelope specification
│   ├── detection_result_schema.md # Output schema & confidence policy specification
│   ├── backend_integration.md     # Step-by-step Member 1 handoff guide
│   └── security_testing.md        # Testing methodology & regression catalogue
├── requirements.txt               # Dependencies declaration (Standard Library only)
└── README.md                      # This master README file
```

---

## 4. Quickstart: Running Tests

The test suite runs using Python's standard `unittest` framework without installing third-party test runners:

```bash
# Execute the entire test suite (131 tests)
python -m unittest discover -s Tests -p "Test_*.py" -v
```

Expected output:
```
Ran 131 tests in 0.012s

OK
```

---

## 5. Quickstart: In-Process Backend Usage

To analyze an ingested event dictionary from Django:

```python
from CyberSecurity.Integration import evaluate_for_backend

# Ingested event data from Django SecurityEvent model
event = {
    "event_id": 101,
    "path": "/api/products",
    "query": {"category": "1 UNION SELECT username, password FROM users --"},
    "source_ip": "198.51.100.25"
}

# Run detection evaluation
result = evaluate_for_backend(event)

# Inspect validated result formatted for Member 1's DRF Serializer
print(result)
# Output:
# {
#   "event_id": 101,
#   "rule_detected": True,
#   "rule_confidence": 0.0,
#   "attack_type": "SQL Injection",
#   "evidence": "[SQLI-001] Suspicious SQL keyword combination; [SQLI-004] Explicit UNION-SELECT query pattern",
#   "severity": "high"
# }
```

---

## 6. Implemented Detection Rule Summary

The module implements **30 detection rules** across 10 security domains:

| Category | Rules | Primary MITRE ATT&CK | Primary CWE | Primary OWASP |
| :--- | :--- | :--- | :--- | :--- |
| **SQL Injection** | `SQLI-001` - `004` | T1190 (Exploit Public-Facing App) | CWE-89 | 2021-A03 |
| **Cross-Site Scripting** | `XSS-001` - `003` | T1059.007 (JavaScript) | CWE-79 | 2021-A03 |
| **Brute Force** | `BRUTE-001` | T1110.001 (Password Guessing) | CWE-307 | 2021-A07 |
| **Command Injection** | `CMDI-001` - `003` | T1059.004 (Unix Shell) | CWE-78 | 2021-A03 |
| **Path Traversal** | `PTRAV-001` - `003` | T1083 (File & Directory Discovery)| CWE-22 | 2021-A01 |
| **SSRF** | `SSRF-001` - `003` | T1090 (Proxy), T1552.005 (Cloud Meta)| CWE-918 | 2021-A10 |
| **IDOR / Access Control**| `IDOR-001` - `002` | T1078 (Valid Accounts) | CWE-639 | 2021-A01 |
| **Session Security** | `SESSION-001` - `002`| T1539 (Steal Web Session Cookie) | CWE-384 | 2021-A07 |
| **API Security** | `API-001` - `003` | T1078 (Valid Accounts) | CWE-287 | API 2023-API2 |
| **Security Misconfiguration**| `MISCONFIG-001` - `006`| T1082 (System Info Discovery) | CWE-16, 693 | 2021-A05 |

For complete rule definitions, regex patterns, and mitigation details, see [`Docs/detection_rules.md`](file:///c:/Users/ARNAV%20GUPTA/Desktop/projects/ThreatLens/CyberSecurity/Docs/detection_rules.md).

