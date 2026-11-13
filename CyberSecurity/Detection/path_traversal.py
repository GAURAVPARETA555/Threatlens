
import re
from typing import Any
from urllib.parse import unquote


PATH_TRAVERSAL_RULES = {
    "PTRAV-001": "Parent-directory traversal sequence detected",
    "PTRAV-002": "Encoded parent-directory traversal detected",
    "PTRAV-003": "Sensitive file path pattern detected",
}

MAX_FIELD_LENGTH = 100_000
MAX_DECODE_PASSES = 3


def normalize_text(value: Any) -> str:
    """Convert request data to bounded, normalized searchable text."""

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

    return text.replace("\\", "/").lower()


def extract_request_data(event: dict) -> str:
    """Extract URL and request data relevant to path traversal."""

    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")

    parts = []

    for field in ("path", "query", "body"):
        value = event.get(field)
        if value is not None:
            parts.append(normalize_text(value))

    return " ".join(parts)


def detect_path_traversal(event: dict) -> dict:
    """
    Detect common path traversal indicators in request data.

    Detection indicates suspicious input; it does not prove that a
    file was accessed or that the application is vulnerable.
    """

    request_data = extract_request_data(event)
    evidence = []

    # Match parent-directory segments after URL decoding and
    # slash normalization, including repeated traversal sequences.
    traversal_pattern = re.compile(
        r"(?:^|/)\.\.(?:/|$)"
    )

    if traversal_pattern.search(request_data):
        evidence.append({
            "rule_id": "PTRAV-001",
            "description": PATH_TRAVERSAL_RULES["PTRAV-001"],
        })

    # Identify traversal notation that was URL-encoded in the
    # original request. The normalized value is used for detection.
    original_parts = [
        str(event.get(field, ""))
        for field in ("path", "query", "body")
        if event.get(field) is not None
    ]
    original_data = " ".join(original_parts).lower()

    encoded_traversal_pattern = re.compile(
        r"%(?:2e|2f|5c)", re.IGNORECASE
    )

    if (
        encoded_traversal_pattern.search(original_data)
        and traversal_pattern.search(request_data)
    ):
        evidence.append({
            "rule_id": "PTRAV-002",
            "description": PATH_TRAVERSAL_RULES["PTRAV-002"],
        })

    sensitive_file_pattern = re.compile(
        r"(?:^|/)(?:etc/passwd|etc/shadow|"
        r"windows/win\.ini)(?:$|[/?#\s])",
        re.IGNORECASE,
    )

    if sensitive_file_pattern.search(request_data):
        evidence.append({
            "rule_id": "PTRAV-003",
            "description": PATH_TRAVERSAL_RULES["PTRAV-003"],
        })

    # Keep one evidence entry per rule even if multiple fields match.
    unique_evidence = []
    seen_rule_ids = set()

    for item in evidence:
        if item["rule_id"] not in seen_rule_ids:
            unique_evidence.append(item)
            seen_rule_ids.add(item["rule_id"])

    detected = bool(unique_evidence)

    return {
        "rule_detected": detected,
        "attack_type": "Path Traversal" if detected else None,
        "severity": "High" if detected else None,
        "confidence": 0.0,
        "evidence": unique_evidence,
        "source": "security_rule",
    }
