"""
Canonical schema definitions and mapping constants for ThreatLens backend integration.
"""

from typing import Final

CANONICAL_EVENT_FIELDS: Final[set[str]] = {
    "event_id",
    "timestamp",
    "source_ip",
    "endpoint",
    "http_method",
    "path",
    "query",
    "body",
    "headers",
    "event_type",
    "outcome",
    "username",
    "response",
    "authorization",
    "session",
    "api_security",
    "telemetry",
}

# Map internal title-case severities to Django choices: ('low', 'medium', 'high', 'critical')
SEVERITY_BACKEND_MAP: Final[dict[str, str]] = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

# Deterministic hierarchy for primary attack selection when multiple detectors trigger
ATTACK_PRIORITY: Final[list[str]] = [
    "OS Command Injection",
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Server-Side Request Forgery (SSRF)",
    "Path Traversal",
    "Brute Force",
    "Broken Access Control / IDOR Indicator",
    "Authentication & Session Security",
    "API Security Indicator",
    "Security Misconfiguration",
]

# Canonical mapping from internal detector attack names to backend Attack model names
ATTACK_NAME_ALIASES: Final[dict[str, str]] = {
    "SQL Injection": "SQL Injection",
    "Cross-Site Scripting (XSS)": "Cross-Site Scripting (XSS)",
    "OS Command Injection": "Command Injection",
    "Path Traversal": "Path Traversal",
    "Server-Side Request Forgery (SSRF)": "SSRF",
    "Brute Force": "Brute Force",
    "Broken Access Control / IDOR Indicator": "IDOR",
    "Security Misconfiguration": "Security Misconfiguration",
    "Authentication & Session Security": "Session Security",
    "API Security Indicator": "API Security",
}

