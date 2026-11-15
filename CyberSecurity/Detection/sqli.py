import re
from typing import Any


SQLI_RULES = {
    "SQLI-001": "Suspicious SQL keyword combination",
    "SQLI-002": "Boolean SQL manipulation pattern",
    "SQLI-003": "SQL comment manipulation pattern",
    "SQLI-004": "UNION-based SQL injection pattern",
}


def normalize_text(value: Any) -> str:
    """
    Convert request data into a normalized string for analysis.

    The detector currently performs basic URL-style decoding and
    whitespace normalization.
    """
    if value is None:
        return ""

    text = str(value)

    # Decode common percent-encoded URL characters.
    try:
        from urllib.parse import unquote

        text = unquote(text)
    except Exception:
        pass

    # Normalize whitespace.
    text = re.sub(r"\s+", " ", text)

    return text.strip().lower()


def extract_request_data(event: dict) -> str:
    """
    Extract relevant request fields from a security event.

    This keeps the detector independent from Django.
    """
    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")

    parts = []

    for field in ("path", "query", "body"):
        value = event.get(field)

        if value:
            parts.append(normalize_text(value))

    return " ".join(parts)


def detect_sqli(event: dict) -> dict:
    """
    Analyze a security event for SQL Injection indicators.

    Returns a structured cybersecurity detection result.
    """
    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")

    request_data = extract_request_data(event)

    evidence = []

    # SQLI-001:
    # Multiple SQL keywords appearing together.
    sql_keyword_pattern = re.compile(
        r"\b(union\s+select|select\s+.+\s+from|"
        r"insert\s+into|update\s+.+\s+set|delete\s+from)\b",
        re.IGNORECASE,
    )

    if sql_keyword_pattern.search(request_data):
        evidence.append({
            "rule_id": "SQLI-001",
            "description": SQLI_RULES["SQLI-001"],
        })

    # SQLI-002:
    # Boolean manipulation indicators combined with quotation.
    boolean_pattern = re.compile(
        r"""(['"]\s*(or|and)\s+['"]?\w+['"]?\s*=\s*['"]?\w+)""",
        re.IGNORECASE,
    )

    if boolean_pattern.search(request_data):
        evidence.append({
            "rule_id": "SQLI-002",
            "description": SQLI_RULES["SQLI-002"],
        })

    # SQLI-003:
    # SQL comment syntax combined with other SQL indicators.
    comment_pattern = re.compile(
        r"(--|#|/\*)",
        re.IGNORECASE,
    )

    sql_context_pattern = re.compile(
        r"\b(select|union|insert|update|delete|from|where|or|and)\b",
        re.IGNORECASE,
    )

    if (
        comment_pattern.search(request_data)
        and sql_context_pattern.search(request_data)
    ):
        evidence.append({
            "rule_id": "SQLI-003",
            "description": SQLI_RULES["SQLI-003"],
        })

    # SQLI-004:
    # UNION + SELECT is a particularly strong SQLi indicator.
    union_pattern = re.compile(
        r"\bunion\s+(all\s+)?select\b",
        re.IGNORECASE,
    )

    if union_pattern.search(request_data):
        evidence.append({
            "rule_id": "SQLI-004",
            "description": SQLI_RULES["SQLI-004"],
        })

    detected = len(evidence) > 0

    return {
        "attack_type": "SQL Injection" if detected else None,
        "severity": "High" if detected else None,
        "confidence": 0.0,
        "evidence": evidence,
        "source": "security_rule",
        "rule_detected": detected,
    }