
import re
from typing import Any


SECURITY_MISCONFIGURATION_RULES = {
    "MISCONFIG-001": "Missing Content-Security-Policy header",
    "MISCONFIG-002": "Missing X-Content-Type-Options header",
    "MISCONFIG-003": "Missing clickjacking protection header",
    "MISCONFIG-004": "Cookie missing Secure attribute",
    "MISCONFIG-005": "Cookie missing HttpOnly attribute",
    "MISCONFIG-006": "Verbose error or stack trace exposed",
}

STACK_TRACE_PATTERNS = (
    re.compile(r"\btraceback \(most recent call last\):", re.IGNORECASE),
    re.compile(r"\bexception in thread\b", re.IGNORECASE),
    re.compile(r"\bat\s+[\w.$]+\([^)]*:\d+\)", re.IGNORECASE),
    re.compile(r"\b(?:nullreferenceexception|stackoverflowexception)\b", re.IGNORECASE),
)


def _normalize_headers(headers: Any) -> dict[str, str]:
    """Normalize HTTP response headers into lowercase names."""

    if not isinstance(headers, dict):
        return {}

    normalized = {}

    for name, value in headers.items():
        if not isinstance(name, str):
            continue

        if isinstance(value, (list, tuple)):
            value = ", ".join(str(item) for item in value)
        elif value is None:
            value = ""
        else:
            value = str(value)

        normalized[name.strip().lower()] = value.strip()

    return normalized


def _cookie_values(headers: dict[str, str]) -> list[str]:
    """Extract Set-Cookie values, including common list-based inputs."""

    values = []

    for name, value in headers.items():
        if name != "set-cookie":
            continue

        values.extend(
            item.strip()
            for item in value.split("\n")
            if item.strip()
        )

    return values


def detect_security_misconfiguration(event: dict) -> dict:
    """
    Inspect HTTP response metadata for common security weaknesses.

    Expects response data in event["response"], with "headers" and
    optionally "body". Missing response data is not treated as proof
    that a header is absent.
    """

    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")

    response = event.get("response")

    if not isinstance(response, dict):
        return {
            "rule_detected": False,
            "attack_type": None,
            "severity": None,
            "confidence": 0.0,
            "evidence": [],
            "source": "security_rule",
        }

    headers = _normalize_headers(response.get("headers", {}))
    body = response.get("body", "")
    body_text = str(body)[:100_000] if body is not None else ""

    evidence = []

    def add_evidence(rule_id: str, detail: str) -> None:
        evidence.append({
            "rule_id": rule_id,
            "description": SECURITY_MISCONFIGURATION_RULES[rule_id],
            "detail": detail,
        })

    if "content-security-policy" not in headers:
        add_evidence(
            "MISCONFIG-001",
            "Response does not include Content-Security-Policy.",
        )

    if "x-content-type-options" not in headers:
        add_evidence(
            "MISCONFIG-002",
            "Response does not include X-Content-Type-Options.",
        )

    if not (
        "x-frame-options" in headers
        or "content-security-policy" in headers
        and "frame-ancestors" in headers["content-security-policy"].lower()
    ):
        add_evidence(
            "MISCONFIG-003",
            "No X-Frame-Options or CSP frame-ancestors protection found.",
        )

    for cookie in _cookie_values(headers):
        cookie_parts = [
            part.strip().lower()
            for part in cookie.split(";")
        ]
        cookie_name = cookie_parts[0].split("=", 1)[0] if cookie_parts else "unknown"
        attributes = set(cookie_parts[1:])

        if "secure" not in attributes:
            add_evidence(
                "MISCONFIG-004",
                f"Cookie '{cookie_name}' lacks the Secure attribute.",
            )

        if "httponly" not in attributes:
            add_evidence(
                "MISCONFIG-005",
                f"Cookie '{cookie_name}' lacks the HttpOnly attribute.",
            )

    for pattern in STACK_TRACE_PATTERNS:
        if pattern.search(body_text):
            add_evidence(
                "MISCONFIG-006",
                "Response body contains a stack-trace or verbose-error indicator.",
            )
            break

    # Return each rule only once, even if multiple cookies match.
    unique_evidence = []
    seen = set()

    for item in evidence:
        if item["rule_id"] not in seen:
            unique_evidence.append(item)
            seen.add(item["rule_id"])

    detected = bool(unique_evidence)

    return {
        "rule_detected": detected,
        "attack_type": (
            "Security Misconfiguration" if detected else None
        ),
        "severity": "Medium" if detected else None,
        "confidence": 0.0,
        "evidence": unique_evidence,
        "source": "security_rule",
    }
