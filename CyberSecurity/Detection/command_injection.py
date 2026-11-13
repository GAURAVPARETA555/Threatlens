
import re
from typing import Any
from urllib.parse import unquote


COMMAND_INJECTION_RULES = {
    "CMDI-001": "Shell command chaining operator with a command pattern",
    "CMDI-002": "Shell command substitution pattern",
    "CMDI-003": "Suspicious operating-system command pattern",
}

MAX_FIELD_LENGTH = 100_000
MAX_DECODE_PASSES = 2


def normalize_text(value: Any) -> str:
    """Convert request data into bounded, searchable text."""

    if value is None:
        return ""

    if isinstance(value, dict):
        text = " ".join(
            f"{normalize_text(key)} {normalize_text(item)}"
            for key, item in value.items()
        )
    elif isinstance(value, (list, tuple)):
        text = " ".join(normalize_text(item) for item in value)
    else:
        text = str(value)

    text = text[:MAX_FIELD_LENGTH]

    for _ in range(MAX_DECODE_PASSES):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded

    return re.sub(r"\s+", " ", text).strip().lower()


def extract_request_data(event: dict) -> str:
    """Extract path, query, and body data without mutating the event."""

    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")

    parts = []

    for field in ("path", "query", "body"):
        value = event.get(field)
        if value is not None:
            parts.append(normalize_text(value))

    return " ".join(parts)


def detect_command_injection(event: dict) -> dict:
    """
    Detect common command-injection indicators in request data.

    A match is a suspicious indicator, not proof that a command
    executed or that the application is vulnerable.
    """

    request_data = extract_request_data(event)
    evidence = []

    patterns = (
        (
            "CMDI-001",
            re.compile(
                r"(?:;|\||&&|\|\|)\s*"
                r"(?:whoami|id|uname|pwd|cat|ls|dir|"
                r"ping|curl|wget|ipconfig|ifconfig)\b",
                re.IGNORECASE,
            ),
        ),
        (
            "CMDI-002",
            re.compile(
                r"(?:\$\([^)]{1,200}\)|`[^`]{1,200}`)",
                re.IGNORECASE,
            ),
        ),
        (
            "CMDI-003",
            re.compile(
                r"(?:^|\s)(?:whoami|uname|ifconfig|ipconfig)(?:\s|$)"
                r"|(?:\b(?:/usr/bin/id|/bin/id)\b|\bid\s+-[a-z]+)",
                re.IGNORECASE,
            ),
        ),
    )

    for rule_id, pattern in patterns:
        if pattern.search(request_data):
            evidence.append({
                "rule_id": rule_id,
                "description": COMMAND_INJECTION_RULES[rule_id],
            })

    detected = bool(evidence)

    return {
        "rule_detected": detected,
        "attack_type": "OS Command Injection" if detected else None,
        "severity": "High" if detected else None,
        "confidence": 0.0,
        "evidence": evidence,
        "source": "security_rule",
    }
