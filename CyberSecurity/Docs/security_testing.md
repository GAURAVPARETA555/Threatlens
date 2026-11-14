# ThreatLens — Security Testing & Verification Guide

## 1. Overview

This document specifies the testing methodology, test suite organization, regression prevention framework, and verification procedures for the ThreatLens `CyberSecurity` module.

The module incorporates an automated test suite executed via Python's standard `unittest` framework or `pytest`, with **131 automated tests** currently passing at 100% with zero regressions, zero external network dependencies, and execution time under 0.05 seconds.

---

## 2. Test Suite Organization

The test suite is located in the `Tests/` directory and mirrors the modular architecture of the detection engine:

| Test File | Target Module | Test Count | Test Focus & Capabilities |
| :--- | :--- | :---: | :--- |
| `Test_sqli.py` | `Detection/sqli.py` | 5 | Keyword combinations, Boolean manipulation, comment syntax, UNION attacks, input type safety. |
| `Test_xss.py` | `Detection/xss.py` | 8 | `<script>` tags, event handlers, javascript: URIs, URL decoding passes, nested dict structures, benign payloads. |
| `Test_brute_force.py` | `Detection/brute_force.py` | 20 | Sliding window thresholds, expiry, multi-IP isolation, multi-user evidence, success reset, bounded memory pruning, naive & lenient UTC parsing, batch ingestion safety. |
| `Test_command_injection.py` | `Detection/command_injection.py` | 15 | Command chaining, backtick/subshell substitution, binary names, `id` parameter false-positive mitigation, clean query parameters. |
| `Test_path_traversal.py` | `Detection/path_traversal.py` | 8 | `../` sequences, Windows backslashes, double encoding `%252e`, critical file targets (`/etc/passwd`, `win.ini`), benign numeric decimals. |
| `Test_ssrf.py` | `Detection/ssrf.py` | 17 | IPv4/IPv6 loopback, `0.0.0.0` unspecified address, `localhost` hostnames, subdomains, RFC 1918 private IPs, AWS/GCP cloud metadata endpoints, malformed URLs. |
| `Test_idor.py` | `Detection/idor.py` | 7 | Telemetry extraction, policy decisions (`deny`/`allow`), ownership mismatch indicators, empty/missing envelopes. |
| `Test_session_security.py` | `Detection/session_security.py` | 8 | Session fixation (token non-rotation after auth), post-logout reuse, benign token rotations, missing session context. |
| `Test_api_security.py` | `Detection/api_security.py` | 8 | Rejected auth tokens, invalid API keys, rate limit enforcement indicators, benign API traffic. |
| `Test_security_misconfiguration.py` | `Detection/security_misconfiguration.py` | 8 | Missing CSP, X-Content-Type-Options, X-Frame-Options, insecure cookies (`Secure`, `HttpOnly`), server stack trace disclosure. |
| `Test_engine.py` | `Detection/engine.py` | 18 | Central coordination, multi-detector aggregation, severity ordering, event ID propagation, uncalibrated confidence status, error isolation, dynamic registry. |
| `Test_integration_adapter.py` | `Integration/adapter.py` | 9 | DRF serializer contract compliance, primary attack resolution, evidence text formatting, strict confidence policy rejection, input non-mutation. |
| **Total** | **12 Test Suites** | **131** | **100% Pass Rate (0 Failures, 0 Errors, 0 Skipped)** |

---

## 3. Running the Test Suite

### 3.1 Standard unittest (Standard Library)

Run all tests from the repository root or the `CyberSecurity` module directory:

```bash
# From within the CyberSecurity directory
python -m unittest discover -s Tests -p "Test_*.py" -v
```

Run a specific detector test suite:

```bash
python -m unittest Tests.Test_sqli -v
python -m unittest Tests.Test_brute_force -v
python -m unittest Tests.Test_integration_adapter -v
```

### 3.2 pytest (Optional)

If `pytest` is installed in your Python environment:

```bash
pytest Tests/ -v
```

---

## 4. Test Categories & Verification Scope

### 4.1 True Positive Verification (Known Attacks)
Each detector is validated against canonical and modern attack representations:
- **SQLi:** `' OR 1=1 --`, `UNION SELECT null, username, password FROM users`, `INSERT INTO logs`.
- **XSS:** `<script>alert(1)</script>`, `<img src=x onerror=prompt(1)>`, `javascript:alert(document.cookie)`.
- **Command Injection:** `; id`, `| whoami`, `&& uname -a`, `$(id)`, `` `cat /etc/passwd` ``.
- **Path Traversal:** `../../../../etc/passwd`, `..\\..\\windows\\win.ini`, `%252e%252e%252f`.
- **SSRF:** `http://127.0.0.1:8080`, `http://localhost/admin`, `http://169.254.169.254/latest/meta-data/`.
- **Brute Force:** Sustained authentication bursts from identical IP addresses exceeding configured thresholds.

### 4.2 True Negative Verification (Benign Traffic)
Detectors must not flag standard web traffic:
- Legitimate search queries: `?q=how+to+use+python`.
- Safe parameters containing technical keywords: `?param=select_item`, `?action=update_profile`.
- Common identity and pagination fields: `{"id": 105, "order_id": 9920}` (verifies `CMDI-003` does not alert).
- Safe public URLs: `https://www.google.com`, `https://example.com/api`.
- Valid authentication sequences where failed attempts stay below threshold or reset upon successful login.

### 4.3 Edge Case & Robustness Testing
- **Multi-Level Encoding:** Verifies double URL encoding (`%252f`, `%252e`) and mixed casing (`uNiOn sElEcT`).
- **Nested & Malformed Payloads:** Verifies that deeply nested dictionaries, non-string JSON values, integers, lists, and `None` values do not cause unhandled runtime exceptions.
- **Length Boundaries:** Safe handling of oversized inputs (tested up to 100,000 characters).
- **Timezone Resilience:** Verification of ISO 8601 strings with explicit offsets, UTC Z indicators, and timezone-naive datetimes.

### 4.4 Critical Security Regression Tests
1. **Command Injection Standalone ID False Positive (`CMDI-003`):**
   - *Test:* `test_standalone_id_parameter_is_not_detected` in `Test_command_injection.py`.
   - *Verified Behavior:* Parameters like `{"id": 123}` or `?id=5` do not trigger OS command injection.
2. **Brute Force Memory Safety & Eviction:**
   - *Test:* `test_bounded_state_evicts_oldest_entries` in `Test_brute_force.py`.
   - *Verified Behavior:* Prevents memory leaks by pruning tracked IP cache when exceeding `max_tracked_entries`.
3. **Brute Force Safe Timestamp Fallback in Lenient Mode:**
   - *Test:* `test_batch_historical_ingestion_with_invalid_timestamps_does_not_alert` in `Test_brute_force.py`.
   - *Verified Behavior:* Batch ingestion of historical logs with missing or malformed timestamps never generates false `BRUTE-001` alerts.
4. **SSRF Loopback & Unspecified Address Hardening:**
   - *Tests:* `test_localhost_hostname_is_detected`, `test_unspecified_address_0_0_0_0_is_detected` in `Test_ssrf.py`.
   - *Verified Behavior:* Detects `localhost`, `localhost.localdomain`, `*.localhost`, and `0.0.0.0` destinations.
5. **Engine Exception Isolation:**
   - *Test:* `test_detector_exception_is_isolated_and_reported` in `Test_engine.py`.
   - *Verified Behavior:* A misbehaving or buggy detector cannot crash the central engine or disrupt other detectors.

---

## 5. Adding New Rules & Test Procedures

When introducing new detection rules or expanding existing modules, developers should adhere to the following test-driven procedure:

### Step 1: Write True-Positive and True-Negative Tests First
Add unit tests in the appropriate `Tests/Test_<detector>.py` module before writing detection regex or logic.

```python
def test_new_attack_vector_is_detected(self):
    detector = SQLInjectionDetector()
    event = {"query": {"filter": "SLEEP(5)"}}
    result = detector.detect(event)
    self.assertTrue(result["detected"])
    rule_ids = [e["rule_id"] for e in result["evidence"]]
    self.assertIn("SQLI-006", rule_ids)

def test_benign_input_matching_new_rule_is_not_flagged(self):
    detector = SQLInjectionDetector()
    event = {"query": {"filter": "sleep_mode_enabled"}}
    result = detector.detect(event)
    self.assertFalse(result["detected"])
```

### Step 2: Implement Detection Rule
Implement pattern matching inside `Detection/<module>.py`. Ensure:
- String normalization (URL decoding, lowercasing, whitespace trimming).
- Input type checking (`isinstance(event, dict)`).
- Input length truncation guard.
- Non-empty evidence generation with explicit `rule_id` and descriptive text.

### Step 3: Run Full Regression Suite
Execute the entire test suite to ensure the new rule introduces zero regressions across existing tests:
```bash
python -m unittest discover -s Tests -p "Test_*.py" -v
```
Ensure all tests pass and test execution time remains under 0.1 seconds.

