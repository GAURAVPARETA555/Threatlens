# ThreatLens — Attack Taxonomy

## 1. Purpose

This document defines the web security attack and telemetry indicator categories analyzed by the ThreatLens `CyberSecurity` detection engine.

ThreatLens distinguishes between:
1. **Stateless Input Attack Patterns:** Malicious payloads detected in HTTP request components (`path`, `query`, `body`).
2. **Stateful Behavioral Anomalies:** Temporal abuse patterns (e.g., failed authentication bursts).
3. **Upstream Security Telemetry Indicators:** Signals forwarded by application middleware, reverse proxies, and identity providers (e.g., policy denials, header audits, API enforcement).

Detection of an attack pattern indicates suspicious activity; it does not by itself prove application vulnerability or successful compromise.

---

## 2. Supported Attack & Indicator Categories

| ID | Category | Detection Paradigm | Primary OWASP Mapping | Primary CWE | Implementation Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SQLI** | SQL Injection | Stateless Input Inspection | OWASP 2021 A03 (Injection) | CWE-89 | **Active** (Rules `SQLI-001` to `SQLI-004`) |
| **XSS** | Cross-Site Scripting | Stateless Input Inspection | OWASP 2021 A03 (Injection) | CWE-79 | **Active** (Rules `XSS-001` to `XSS-003`) |
| **BRUTE** | Brute Force (Authentication) | Stateful Sliding Window | OWASP 2021 A07 (Auth Failures) | CWE-307 | **Active** (Rule `BRUTE-001`) |
| **CMDI** | OS Command Injection | Stateless Input Inspection | OWASP 2021 A03 (Injection) | CWE-78 | **Active** (Rules `CMDI-001` to `CMDI-003`) |
| **PTRAV** | Path Traversal | Stateless Input Inspection | OWASP 2021 A01 (Broken Access) | CWE-22 | **Active** (Rules `PTRAV-001` to `PTRAV-003`) |
| **SSRF** | Server-Side Request Forgery | Stateless Input Inspection | OWASP 2021 A10 (SSRF) | CWE-918 | **Active** (Rules `SSRF-001` to `SSRF-003`) |
| **IDOR** | Broken Access Control / IDOR | Telemetry Flag Audit | OWASP 2021 A01 (Broken Access) | CWE-639 | **Active** (Rules `IDOR-001`, `IDOR-002`) |
| **SESSION** | Session & Auth Security | Telemetry Diff Audit | OWASP 2021 A07 (Auth Failures) | CWE-384 | **Active** (Rules `SESSION-001`, `SESSION-002`) |
| **API** | API Security Indicator | Telemetry Status Audit | OWASP API 2023 API2 (Broken Auth) | CWE-287 | **Active** (Rules `API-001` to `API-003`) |
| **MISCONFIG**| Security Misconfiguration | Response Header/Body Audit | OWASP 2021 A05 (Misconfiguration) | CWE-16, CWE-693 | **Active** (Rules `MISCONFIG-001` to `MISCONFIG-006`) |
| **SUSP** | Suspicious Request Structure | Structural Protocol Heuristic | OWASP 2021 A04 (Insecure Design) | CWE-20 | **Roadmap** (Planned Phase 2) |
| **RATE** | Volumetric Request Rate Anomaly | Stateful Distributed Rate Counter | OWASP API 2023 API4 (Resource Consumption) | CWE-770 | **Roadmap** (Planned Phase 2) |

---

## 3. Detection Scope & Boundaries

1. **Controlled Environment:** All rules and validation tests are designed for authorized defensive analysis in simulated, development, or academic environments.
2. **Payload Extraction:** String pattern detectors operate over decoded and normalized URL components (`path`, `query`, `body`).
3. **State Management:** Stateful modules maintain bounded in-memory sliding windows. Distributed multi-process tracking requires an external state store (e.g., Redis).
4. **No Automated Exploitation:** The engine inspects and classifies security events. It never attempts active exploitation, DNS resolution, or outbound connectivity.
