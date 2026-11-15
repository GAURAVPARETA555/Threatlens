# ThreatLens — CyberSecurity Documentation Index

## 1. Welcome to Member 4 Documentation

This directory contains complete technical specifications, architectural documentation, detection rule catalogs, and integration handoff guides for the **ThreatLens CyberSecurity Detection Engineering Module (Member 4)**.

---

## 2. Documentation Directory Map

| Document | Primary Audience | Description |
| :--- | :--- | :--- |
| [`attack_taxonomy.md`](file:///c:/Users/ARNAV%20GUPTA/Desktop/projects/ThreatLens/CyberSecurity/Docs/attack_taxonomy.md) | All Members, Security Reviewers | Complete categorization of web security attacks, indicators, and mappings to OWASP Top 10 (2021), OWASP API Security Top 10 (2023), CWE, and MITRE ATT&CK. |
| [`detection_rules.md`](file:///c:/Users/ARNAV%20GUPTA/Desktop/projects/ThreatLens/CyberSecurity/Docs/detection_rules.md) | Security Engineers, Auditors | Comprehensive catalog of all 30 implemented detection rules across the 10 detection modules, including regex logic, normalization, evidence, and false positive/negative analysis. |
| [`security_event_schema.md`](file:///c:/Users/ARNAV%20GUPTA/Desktop/projects/ThreatLens/CyberSecurity/Docs/security_event_schema.md) | Member 1 (Django), Member 4 (Security) | Exact specification of the input event envelope accepted by `Detection.engine.analyze_event()`. |
| [`detection_result_schema.md`](file:///c:/Users/ARNAV%20GUPTA/Desktop/projects/ThreatLens/CyberSecurity/Docs/detection_result_schema.md) | Member 1 (Django), Member 2 (React), Member 3 (ML) | Comprehensive reference for canonical engine output and backend integration serializer contracts, multi-detector aggregation, and confidence policies. |
| [`backend_integration.md`](file:///c:/Users/ARNAV%20GUPTA/Desktop/projects/ThreatLens/CyberSecurity/Docs/backend_integration.md) | **Member 1 (Django Backend Lead)** | **Primary handoff document for Member 1.** Step-by-step implementation guide, sample Django view code, risk engine integration, error handling, and performance notes. |
| [`security_testing.md`](file:///c:/Users/ARNAV%20GUPTA/Desktop/projects/ThreatLens/CyberSecurity/Docs/security_testing.md) | QA, Security Engineers, Reviewers | Complete testing methodology, breakdown of 131 automated unit and regression tests, coverage details, and instructions for running and adding tests. |

---

## 3. Recommended Reading Paths

### For Member 1 (Backend Integration Lead):
1. Start with [`backend_integration.md`](file:///c:/Users/ARNAV%20GUPTA/Desktop/projects/ThreatLens/CyberSecurity/Docs/backend_integration.md) for quickstart and Django view code.
2. Review [`detection_result_schema.md`](file:///c:/Users/ARNAV%20GUPTA/Desktop/projects/ThreatLens/CyberSecurity/Docs/detection_result_schema.md) to understand field serialization into `DetectionAnalyzeSerializer`.
3. Consult [`security_event_schema.md`](file:///c:/Users/ARNAV%20GUPTA/Desktop/projects/ThreatLens/CyberSecurity/Docs/security_event_schema.md) to verify telemetry forwarded from `SecurityEvent` models.

### For Security Auditors & Project Evaluators:
1. Start with [`attack_taxonomy.md`](file:///c:/Users/ARNAV%20GUPTA/Desktop/projects/ThreatLens/CyberSecurity/Docs/attack_taxonomy.md) for industry standard mappings (OWASP, CWE, MITRE ATT&CK).
2. Examine [`detection_rules.md`](file:///c:/Users/ARNAV%20GUPTA/Desktop/projects/ThreatLens/CyberSecurity/Docs/detection_rules.md) for concrete detection logic, pattern regex, and remediation history.
3. Review [`security_testing.md`](file:///c:/Users/ARNAV%20GUPTA/Desktop/projects/ThreatLens/CyberSecurity/Docs/security_testing.md) for automated test coverage and regression safeguards.

---

## 4. Verification Quick Commands

From the `CyberSecurity` module directory:

```bash
# Run all 131 unit tests
python -m unittest discover -s Tests -p "Test_*.py" -v

# Run Integration Adapter tests specifically
python -m unittest Tests.Test_integration_adapter -v
```

