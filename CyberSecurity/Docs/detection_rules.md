# ThreatLens — Comprehensive Detection Rules Specification

This document details all 30 detection rules implemented across the 10 detection modules in ThreatLens `CyberSecurity`.

---

## 1. SQL Injection (`Detection/sqli.py`)

### General Logic
Inspects request components (`path`, `query`, `body`) after URL decoding and whitespace squashing. Severity: **High**. Confidence: **0.0**.

| Rule ID | Name | Detection Pattern | False Positives | False Negatives |
| :--- | :--- | :--- | :--- | :--- |
| `SQLI-001` | Keyword Combinations | Pairs of SQL keywords: `UNION SELECT`, `SELECT ... FROM`, `INSERT INTO`, `UPDATE ... SET`, `DELETE FROM`. | Legitimate administrative or technical text (e.g. documentation, support requests). | Single keyword injections or non-adjacent keywords. |
| `SQLI-002` | Boolean Manipulation | Quotes followed by logical operators (`OR`/`AND`) and equality tests (e.g., `' OR '1'='1`). | Natural language text with quotes and Boolean connectors. | Numerical boolean injections without quotation (e.g., `1 OR 1=1`). |
| `SQLI-003` | Comment Manipulation | SQL comment syntax (`--`, `#`, `/*`) combined with SQL context keywords. | Legitimate dashes in queries (e.g. `hello--world`) when SQL words appear nearby. | Comments without recognized keywords. |
| `SQLI-004` | UNION-Based Injection | Explicit union-select combinations: `\bunion\s+(all\s+)?select\b`. | Very low; strong indicator of SQL injection attempt. | Obfuscated union statements (e.g., `UN/**/ION SELECT`). |

*Note: `SQLI-005` (Encoded SQL Injection) was an early design proposal and is not an active standalone rule ID; normalization handles decoding directly.*

---

## 2. Cross-Site Scripting (`Detection/xss.py`)

### General Logic
Inspects `path`, `query`, and `body` (supporting nested structures) up to 100,000 characters and 2 unquote passes. Severity: **High**. Confidence: **0.0**.

| Rule ID | Name | Detection Pattern | False Positives | False Negatives |
| :--- | :--- | :--- | :--- | :--- |
| `XSS-001` | HTML Script Element | Opening `<script` tag. | Technical articles, code snippets, documentation inputs. | Injections without script tags (e.g. `<img onerror=...>`, `<svg/onload=...>`). |
| `XSS-002` | Event-Handler Attributes | Common HTML event handlers (`onerror=`, `onload=`, `onclick=`, etc.). | Parameter names or values coincidentally containing event names (e.g. `?search=onload=true`). | Obfuscated event handlers, SVG animate tags, or unlisted attributes. |
| `XSS-003` | JavaScript URI | `javascript:` pseudo-protocol URI. | Educational text discussing JavaScript protocol. | Case variations with whitespace/comments (e.g., `java/* */script:`). |

---

## 3. Brute Force Detection (`Detection/brute_force.py`)

### General Logic
Maintains an in-process, thread-safe sliding window tracking failed authentication attempts per `source_ip` (and optional `username`). Severity: **High**. Confidence: **0.0**.

| Rule ID | Name | Trigger Condition | Hardening & Stabilization (Phase 1) |
| :--- | :--- | :--- | :--- |
| `BRUTE-001` | Repeated Failed Logins | Count of failed authentication events from the same source IP reaches threshold (default: 5 attempts within 300 seconds). | - **Outcome Handling:** Only `outcome="failure"` increments counter. `outcome="success"` clears previous failures for that IP and never alerts.<br>- **Timestamp Safety:** Lenient mode parses naive timestamps as UTC and handles missing timestamps safely without crashing.<br>- **Bounded Memory:** Evicts stale records and enforces a max key limit (default: 10,000 tracked IPs) to prevent unbounded memory growth. |

---

## 4. OS Command Injection (`Detection/command_injection.py`)

### General Logic
Inspects request components for command chaining, subshell substitution, and system diagnostic binaries. Severity: **High**. Confidence: **0.0**.

| Rule ID | Name | Detection Pattern | False-Positive Mitigation (Phase 1) |
| :--- | :--- | :--- | :--- |
| `CMDI-001` | Chaining Operator with Command | Chaining operators (`;`, `\|`, `&&`, `\|\|`) followed by system commands (`whoami`, `id`, `uname`, `cat`, etc.). | High fidelity; requires an operator plus executable token. |
| `CMDI-002` | Command Substitution | Subshell execution syntax: `$(...)` or backticks `` `...` ``. | High fidelity; targets Unix shell expansion syntax. |
| `CMDI-003` | Suspicious OS Command | Diagnostic binaries: `whoami`, `uname`, `ifconfig`, `ipconfig`, `/usr/bin/id`, or `id` with command flags (e.g., `id -u`). | **Stabilized:** Standalone `id` token removed. Ordinary JSON keys (`{"id": 101}`) or query parameters (`?id=5`) no longer trigger false alerts. |

---

## 5. Path Traversal (`Detection/path_traversal.py`)

### General Logic
Inspects normalized request strings for parent-directory references and sensitive operating-system file targets. Severity: **High**. Confidence: **0.0**.

| Rule ID | Name | Detection Pattern | Target Indicators |
| :--- | :--- | :--- | :--- |
| `PTRAV-001` | Traversal Sequence | Parent-directory segment: `(?:^\|/)\.\.(?:/\|$)`. | Standard traversal sequences (`../`, `..\`). |
| `PTRAV-002` | Encoded Traversal | Traversal sequence present in decoded text while hex percent-encodings (`%2e`, `%2f`, `%5c`) exist in raw input. | Evasion attempts via URL encoding. |
| `PTRAV-003` | Sensitive File Target | Well-known target file paths: `etc/passwd`, `etc/shadow`, `windows/win.ini`. | Critical OS targets. |

---

## 6. Server-Side Request Forgery (`Detection/ssrf.py`)

### General Logic
Extracts HTTP/HTTPS URLs from request fields, parses hostnames, and classifies destinations using IP and domain lookups. Severity: **High**. Confidence: **0.0**.

| Rule ID | Name | Detection Logic | Hostname Hardening (Phase 1) |
| :--- | :--- | :--- | :--- |
| `SSRF-001` | Loopback Destination | Destination resolves to loopback IP (`127.0.0.0/8`, `::1`), unspecified address (`0.0.0.0`), or loopback hostname. | **Stabilized:** Added detection for `localhost`, `localhost.localdomain`, `ip6-localhost`, `ip6-loopback`, and `*.localhost` subdomains. |
| `SSRF-002` | Private/Link-Local IP | Destination is an RFC 1918 private IP (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or link-local (`169.254.0.0/16`). | Prevents internal network pivoting. |
| `SSRF-003` | Cloud Metadata Endpoint | Hostname or IP matches known cloud metadata endpoints. | Includes `169.254.169.254`, `100.100.100.200`, `metadata.google.internal`, `metadata.goog`, `instance-data`. |

---

## 7. Security Misconfiguration (`Detection/security_misconfiguration.py`)

### General Logic
Audits HTTP response headers and bodies forwarded in `event["response"]`. Severity: **Medium**. Confidence: **0.0**.

| Rule ID | Name | Audit Criteria |
| :--- | :--- | :--- |
| `MISCONFIG-001` | Missing CSP | `Content-Security-Policy` header is absent. |
| `MISCONFIG-002` | Missing MIME Sniffing Protection | `X-Content-Type-Options` header is absent. |
| `MISCONFIG-003` | Missing Clickjacking Protection | Neither `X-Frame-Options` nor `CSP frame-ancestors` directive present. |
| `MISCONFIG-004` | Cookie Missing Secure | `Set-Cookie` header lacks `Secure` flag. |
| `MISCONFIG-005` | Cookie Missing HttpOnly | `Set-Cookie` header lacks `HttpOnly` flag. |
| `MISCONFIG-006` | Verbose Stack Trace Exposed | Response body contains stack traces (Python tracebacks, Java exceptions, etc.). |

---

## 8. IDOR / Broken Access Control Indicator (`Detection/idor.py`)

### General Logic
Consumes upstream authorization telemetry forwarded in `event["authorization"]`. Severity: **High**. Confidence: **0.0**.

| Rule ID | Name | Audit Criteria |
| :--- | :--- | :--- |
| `IDOR-001` | Access Denied Indicator | `event["authorization"]["decision"] == "deny"`. |
| `IDOR-002` | Ownership Mismatch Indicator | `event["authorization"]["reason"] == "ownership_mismatch"`. |

---

## 9. Session Security (`Detection/session_security.py`)

### General Logic
Consumes session lifecycle telemetry forwarded in `event["session"]`. Severity: **High**. Confidence: **0.0**.

| Rule ID | Name | Audit Criteria |
| :--- | :--- | :--- |
| `SESSION-001` | Session Fixation Indicator | Successful login occurred but session identifier was unchanged (`before == after`). |
| `SESSION-002` | Post-Logout Reuse | Session token was submitted after explicit logout (`used_after_logout is True`). |

---

## 10. API Security Indicator (`Detection/api_security.py`)

### General Logic
Consumes API gateway telemetry forwarded in `event["api_security"]`. Severity: **Medium**. Confidence: **0.0**.

| Rule ID | Name | Audit Criteria |
| :--- | :--- | :--- |
| `API-001` | Rejected Authentication | API request rejected due to invalid authentication (`authentication_status == "rejected"`). |
| `API-002` | Invalid API Key | API request rejected due to invalid API key (`api_key_status == "invalid"`). |
| `API-003` | Rate Limit Enforcement | API request dropped by upstream rate limiting (`rate_limited is True`). |
