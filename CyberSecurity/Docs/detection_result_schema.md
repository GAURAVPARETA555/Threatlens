# ThreatLens — Detection Result Schema Specification

## 1. Overview

This document specifies the exact structure of detection results produced by the ThreatLens `CyberSecurity` module.

The module provides two output representations:
1. **Canonical Engine Output (`analyze_event`)**: Rich structured result dictionary returned by `Detection.engine.analyze_event()`. Used for internal inspection, diagnostics, multi-detector aggregation, and machine learning feature extraction.
2. **Backend Integration Output (`evaluate_for_backend`)**: Flattened, type-validated dictionary returned by `Integration.adapter.evaluate_for_backend()` or `CyberSecurityAdapter.evaluate_event()`. Matched byte-for-byte to Member 1's Django REST Framework `DetectionAnalyzeSerializer`.

---

## 2. Canonical Engine Output Schema (`analyze_event`)

When an event is evaluated via `Detection.engine.analyze_event(event: dict)`, the engine returns a dictionary conforming to the canonical schema below.

### 2.1 Field Reference

| Field Name | Type | Nullable | Description |
| :--- | :--- | :---: | :--- |
| `event_id` | `int` \| `str` \| `None` | Yes | Preserved from `event.get("event_id")` or `event.get("id")` for log correlation. |
| `rule_detected` | `bool` | No | `True` if at least one detector triggered; `False` if no rules triggered or on benign traffic. |
| `rule_confidence` | `float` | No | Truthful detection confidence score ($0.0 - 1.0$). Fixed at `0.0` pending statistical calibration. |
| `confidence` | `float` | No | Legacy backward-compatibility alias for `rule_confidence`. |
| `confidence_status` | `str` | No | Confidence calibration status metadata: `"uncalibrated"`. |
| `attack_type` | `str` \| `list[str]` \| `None` | Yes | Backward-compatible attack name: scalar string if single attack, list of strings if multiple attacks, `None` if clean. |
| `attack_types` | `list[str]` | No | Canonical list containing all triggered attack category names (always `list[str]`, empty if clean). |
| `severity` | `str` \| `None` | Yes | Highest severity among all triggered rules (`"Critical"`, `"High"`, `"Medium"`, `"Low"`), or `None` if clean. |
| `source` | `str` | No | Constant identifier for the detection origin: `"security_rule"`. |
| `evidence` | `list[dict]` | No | Comprehensive list of evidence dictionaries collected from all triggering detectors. |
| `detector_results` | `list[dict]` | No | Full list of individual detector outcome dictionaries executed during this pass. |
| `errors` | `list[dict]` | No | List of error dictionaries captured from any faulty detectors (isolated by engine try-except). |

### 2.2 Evidence Dictionary Structure

Each entry inside the canonical `evidence` list has the following shape:
```json
{
  "rule_id": "SQLI-001",
  "description": "Suspicious SQL keyword combination"
}
```
Stateful or specialized detectors may include additional descriptive context:
```json
{
  "rule_id": "BRUTE-001",
  "description": "Repeated failed login attempts (5 attempts)",
  "source_ip": "192.0.2.100",
  "usernames": ["admin", "root"],
  "failure_count": 5,
  "window_seconds": 300
}
```

### 2.3 Detector Result Structure

Each entry inside `detector_results` represents the output of a single detection module:
```json
{
  "detected": true,
  "attack_type": "SQL Injection",
  "severity": "High",
  "rule_confidence": 0.0,
  "evidence": [
    {
      "rule_id": "SQLI-001",
      "description": "Suspicious SQL keyword combination"
    }
  ]
}
```

### 2.4 Error Envelope Structure

If an individual detector encounters an unhandled runtime exception, the engine isolates the fault and appends a record to `errors`:
```json
{
  "detector": "SQLInjectionDetector",
  "error": "MemoryError('Out of memory')"
}
```
This ensures zero crashes for the remaining 9 detectors and guarantees the engine always returns a valid dictionary.

---

## 3. Backend Integration Output Schema (`evaluate_for_backend`)

To integrate seamlessly with Member 1's Django backend at `POST /api/detections/analyze/`, the `Integration.adapter.evaluate_for_backend()` adapter transforms the canonical output into the exact contract expected by `DetectionAnalyzeSerializer`.

### 3.1 Field Specification

| Serializer Field | Target DRF Type | Adapting Transformation | Default Value / Rule |
| :--- | :--- | :--- | :--- |
| `event_id` | `serializers.IntegerField()` | Validates positive integer. Extracted from `event_id` or `id`. | Required positive integer. Raises `EventValidationError` if missing/invalid. |
| `rule_detected` | `serializers.BooleanField()` | Direct boolean mapping from engine `rule_detected`. | `True` or `False`. |
| `rule_confidence` | `serializers.FloatField()` | In default mode: returns truthful `0.0` (uncalibrated). In strict mode: raises `ConfidencePolicyError`. | `0.0` (float between 0.0 and 1.0). |
| `attack_type` | `serializers.CharField()` | Deterministic selection of single primary attack name using severity and risk priority hierarchy. Clean events yield `""`. | Formatted string (e.g. `"SQL Injection"` or `""`). |
| `evidence` | `serializers.CharField()` | Formats indicator list into readable bullet string: `"[RULE-001] Description; [RULE-002] Description"`. Clean events yield `""`. | Formatted string or `""`. |
| `severity` | `serializers.CharField()` | Maps engine severity (`"Critical"`, `"High"`, `"Medium"`, `"Low"`) to backend lowercase choices (`"critical"`, `"high"`, `"medium"`, `"low"`). Clean events yield `""`. | Lowercase choice or `""`. |

---

## 4. Multi-Detector Aggregation & Conflict Resolution

When an HTTP request triggers multiple rules across different detectors (e.g., an attack payload combining SQL injection and OS command injection), the engine and adapter apply deterministic resolution rules:

### 4.1 Severity Hierarchy

The composite `severity` field evaluates the maximum weight across all triggered rules:
$$\text{Critical} > \text{High} > \text{Medium} > \text{Low}$$

Numerical weights applied:
- `Critical` = 4
- `High` = 3
- `Medium` = 2
- `Low` = 1

### 4.2 Primary Attack Type Selection Hierarchy

Because Member 1's Django `Alert` and `DetectionAnalyzeSerializer` models accept only a single scalar `attack_type`, the adapter selects a primary attack based on an established risk priority table:

1. `OS Command Injection` (Remote Code Execution risk)
2. `SQL Injection` (Database compromise risk)
3. `Server-Side Request Forgery` (Internal network compromise risk)
4. `Path Traversal` (Local file inclusion / arbitrary read risk)
5. `Cross-Site Scripting (XSS)` (Client-side execution risk)
6. `Broken Access Control / IDOR` (Authorization bypass risk)
7. `Brute Force` (Credential guessing attack)
8. `Session Security` (Session hijacking risk)
9. `API Security` (API enforcement indicator)
10. `Security Misconfiguration` (Passive hardening defect)

All additional attack types and secondary rules remain preserved inside `attack_types` and within the serialized `evidence` text.

---

## 5. Confidence Score Policy

### 5.1 Rationale for `0.0` (Uncalibrated)

Static signature and heuristic pattern rules do not produce true probabilistic confidence values. Assigning arbitrary fabricated numbers (e.g., `0.9` or `0.85`) violates security engineering integrity and corrupts Member 1's risk score calculation:
$$\text{final\_score} = ((\text{rule\_score} \times 0.5) + (\text{ml\_score} \times 0.5)) \times 100$$

### 5.2 Supported Modes

The adapter supports two operational policies via `CyberSecurityAdapter(strict_confidence=...)`:
- **Default Mode (`strict_confidence=False`)**: Emits `rule_confidence=0.0`. Validates against Member 1's `min_value=0, max_value=1` constraint without generating false mathematical certainty.
- **Strict Mode (`strict_confidence=True`)**: Raises `ConfidencePolicyError` if called with uncalibrated confidence. Designed for production pipelines requiring calibrated statistical models before dispatching automated actions.

---

## 6. Concrete JSON Examples

### 6.1 Clean HTTP Request (No Finding)

#### Engine Output (`analyze_event`):
```json
{
  "event_id": 101,
  "rule_detected": false,
  "rule_confidence": 0.0,
  "confidence": 0.0,
  "confidence_status": "uncalibrated",
  "attack_type": null,
  "attack_types": [],
  "severity": null,
  "source": "security_rule",
  "evidence": [],
  "detector_results": [...],
  "errors": []
}
```

#### Backend Integration Output (`evaluate_for_backend`):
```json
{
  "event_id": 101,
  "rule_detected": false,
  "rule_confidence": 0.0,
  "attack_type": "",
  "evidence": "",
  "severity": ""
}
```

### 6.2 Multi-Attack Incident (SQLi + Command Injection)

#### Engine Output (`analyze_event`):
```json
{
  "event_id": 102,
  "rule_detected": true,
  "rule_confidence": 0.0,
  "confidence": 0.0,
  "confidence_status": "uncalibrated",
  "attack_type": ["Command Injection", "SQL Injection"],
  "attack_types": ["Command Injection", "SQL Injection"],
  "severity": "High",
  "source": "security_rule",
  "evidence": [
    {
      "rule_id": "CMDI-001",
      "description": "Command chaining pattern with executable command"
    },
    {
      "rule_id": "SQLI-001",
      "description": "Suspicious SQL keyword combination"
    }
  ],
  "detector_results": [...],
  "errors": []
}
```

#### Backend Integration Output (`evaluate_for_backend`):
```json
{
  "event_id": 102,
  "rule_detected": true,
  "rule_confidence": 0.0,
  "attack_type": "Command Injection",
  "evidence": "[CMDI-001] Command chaining pattern with executable command; [SQLI-001] Suspicious SQL keyword combination",
  "severity": "high"
}
```

