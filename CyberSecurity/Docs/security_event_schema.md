# ThreatLens — Security Event Schema Specification

## 1. Overview

This document specifies the input event envelope accepted by `Detection.engine.analyze_event` and the output structure emitted by the ThreatLens `CyberSecurity` module.

It defines the integration contract between:
- **Member 1:** Django REST Backend (Event Ingestion & Dispatch).
- **Member 4:** Cybersecurity Detection Engine (Rule Evaluation).
- **Member 3:** Machine Learning Pipeline (Feature Analysis).
- **Member 2:** React Security Dashboard (Alert Visualization).

---

## 2. Ingestion Event Schema (`Input`)

Events passed to `analyze_event(event: dict)` must be standard Python dictionaries.

### 2.1 Core Fields

| Field Name | Type | Required | Description | Example |
| :--- | :--- | :---: | :--- | :--- |
| `event_id` | `str` | Optional | Unique UUID or identifier correlating the event with backend database logs. | `"550e8400-e29b-41d4-a716-446655440000"` |
| `event_type` | `str` | Optional | Discriminator for event category (`"http_request"`, `"authentication"`, `"api"`). | `"authentication"` |
| `source_ip` | `str` | Optional* | Origin IP address. (*Mandatory for `BRUTE-001`). | `"192.0.2.50"` |
| `timestamp` | `str` \| `datetime` | Optional* | ISO 8601 timestamp string or datetime object. (*Required for `BRUTE-001`). | `"2026-11-11T12:00:00Z"` |
| `path` | `str` | Optional | HTTP request URL path. | `"/api/v1/search"` |
| `query` | `dict` \| `str` | Optional | Query parameters as dictionary or raw query string. | `{"q": "laptop"}` |
| `body` | `dict` \| `str` | Optional | Request body as parsed JSON dictionary or raw string. | `{"comment": "hello"}` |
| `username` | `str` | Optional | Target account identifier for authentication events. | `"admin_user"` |

### 2.2 Telemetry Envelopes

#### Response Audit Envelope (`event["response"]`)
Audited by `Detection/security_misconfiguration.py`:
```json
{
  "response": {
    "headers": {
      "Content-Type": "text/html",
      "Content-Security-Policy": "default-src 'self'",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Set-Cookie": "session=xyz; Secure; HttpOnly; Path=/"
    },
    "body": "<html>...</html>"
  }
}
```

#### Authorization Telemetry Envelope (`event["authorization"]`)
Audited by `Detection/idor.py`:
```json
{
  "authorization": {
    "decision": "deny",
    "reason": "ownership_mismatch"
  }
}
```

#### Session Telemetry Envelope (`event["session"]`)
Audited by `Detection/session_security.py`:
```json
{
  "session": {
    "event_type": "authentication",
    "authenticated": true,
    "session_id_before": "sess-old-123",
    "session_id_after": "sess-new-456",
    "used_after_logout": false
  }
}
```

#### API Gateway Telemetry Envelope (`event["api_security"]`)
Audited by `Detection/api_security.py`:
```json
{
  "api_security": {
    "authentication_status": "rejected",
    "api_key_status": "invalid",
    "rate_limited": true
  }
}
```

---

## 3. Detection Engine Output Schema (`Output`)

The output of `analyze_event(event: dict)` satisfies both Member 1's backend contract and modern structured inspection requirements:

| Field Name | Type | Nullable | Description |
| :--- | :--- | :---: | :--- |
| `event_id` | `str` | Yes | Preserved from input event for log correlation. |
| `rule_detected` | `bool` | No | `true` if at least one detection rule triggered; `false` otherwise. |
| `rule_confidence` | `float` | No | Detection confidence score ($0.0 - 1.0$). Hardcoded to `0.0` in Phase 1 pending ML calibration. |
| `confidence` | `float` | No | Legacy alias for `rule_confidence` to ensure backward compatibility. |
| `attack_type` | `str` \| `list[str]` \| `None` | Yes | Legacy representation: scalar string if single attack, list of strings if multiple, `None` if clean. |
| `attack_types` | `list[str]` | No | Canonical list of all triggered attack categories (always `list[str]`). |
| `severity` | `str` \| `None` | Yes | Deterministic highest severity (`"Critical"`, `"High"`, `"Medium"`, `"Low"`), or `None` if clean. |
| `evidence` | `list[dict]` | No | Array of indicator dictionaries detailing triggered rule IDs and descriptions. |
| `source` | `str` | No | Origin of detection finding (currently `"security_rule"`). |
| `detector_results` | `list[dict]` | No | Array of all individual detector result dictionaries that executed. |
| `errors` | `list[dict]` | No | Array of errors captured from any faulty detectors (`[{"detector": ..., "error": ...}]`). |

---

## 4. Integration Output Examples

### Example A: Single Finding Output
```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "rule_detected": true,
  "rule_confidence": 0.0,
  "confidence": 0.0,
  "attack_type": "SQL Injection",
  "attack_types": ["SQL Injection"],
  "severity": "High",
  "source": "security_rule",
  "evidence": [
    {
      "rule_id": "SQLI-001",
      "description": "Suspicious SQL keyword combination"
    }
  ],
  "detector_results": [ ... ],
  "errors": []
}
```

### Example B: Multiple Findings Output
```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440001",
  "rule_detected": true,
  "rule_confidence": 0.0,
  "confidence": 0.0,
  "attack_type": ["Cross-Site Scripting (XSS)", "SQL Injection"],
  "attack_types": ["Cross-Site Scripting (XSS)", "SQL Injection"],
  "severity": "High",
  "source": "security_rule",
  "evidence": [
    {
      "rule_id": "XSS-001",
      "description": "HTML script element pattern"
    },
    {
      "rule_id": "SQLI-001",
      "description": "Suspicious SQL keyword combination"
    }
  ],
  "detector_results": [ ... ],
  "errors": []
}
```

### Example C: Clean (No Finding) Output
```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440002",
  "rule_detected": false,
  "rule_confidence": 0.0,
  "confidence": 0.0,
  "attack_type": null,
  "attack_types": [],
  "severity": null,
  "source": "security_rule",
  "evidence": [],
  "detector_results": [ ... ],
  "errors": []
}
```

