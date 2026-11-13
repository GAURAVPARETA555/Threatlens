
import ipaddress
import re
from typing import Any
from urllib.parse import unquote, urlsplit


SSRF_RULES = {
    "SSRF-001": "URL references a loopback address",
    "SSRF-002": "URL references a private or link-local IP address",
    "SSRF-003": "URL references a cloud metadata endpoint",
}

MAX_FIELD_LENGTH = 100_000
MAX_DECODE_PASSES = 2

LOOPBACK_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
}

CLOUD_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
}

CLOUD_METADATA_IPS = {
    "169.254.169.254",
    "100.100.100.200",
    "fd00:ec2::254",
}


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

    return text


def extract_request_data(event: dict) -> str:
    """Extract request path, query, and body data."""

    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")

    parts = []

    for field in ("path", "query", "body"):
        value = event.get(field)
        if value is not None:
            parts.append(normalize_text(value))

    return " ".join(parts)


def _host_from_url(candidate: str) -> str | None:
    """Return a parsed URL hostname, or None if it is not a URL."""

    try:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"}:
            return None
        if not parsed.hostname:
            return None
        return parsed.hostname.rstrip(".").lower()
    except (ValueError, AttributeError):
        return None


def _urls_in_text(text: str) -> list[str]:
    """Extract HTTP(S) URL candidates from arbitrary request text."""

    return re.findall(r"https?://[^\s\"'<>]+", text, re.IGNORECASE)


def _classify_host(host: str) -> list[str]:
    """Return SSRF indicators associated with a parsed hostname."""

    matched_rules = []

    # Check loopback hostnames (e.g. localhost, localhost.localdomain, *.localhost)
    if (
        host in LOOPBACK_HOSTNAMES
        or host.endswith(".localhost")
    ):
        matched_rules.append("SSRF-001")

    # Check cloud metadata endpoint hosts & IPs
    if host in CLOUD_METADATA_HOSTS or host in CLOUD_METADATA_IPS:
        matched_rules.append("SSRF-003")

    # Parse and classify literal IP addresses (IPv4 & IPv6)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None

    if address is not None:
        if address.is_loopback or address.is_unspecified:
            if "SSRF-001" not in matched_rules:
                matched_rules.append("SSRF-001")
        elif address.is_private or address.is_link_local:
            if "SSRF-002" not in matched_rules:
                matched_rules.append("SSRF-002")

    return matched_rules


def detect_ssrf(event: dict) -> dict:
    """
    Detect URLs that reference sensitive network destinations.

    This is an input heuristic. It does not establish that the server
    followed the URL or that an SSRF vulnerability exists.
    """

    request_data = extract_request_data(event)
    evidence = []
    seen_rule_ids = set()

    for candidate in _urls_in_text(request_data):
        host = _host_from_url(candidate.rstrip(".,);]"))

        if host is None:
            continue

        for rule_id in _classify_host(host):
            if rule_id not in seen_rule_ids:
                evidence.append({
                    "rule_id": rule_id,
                    "description": SSRF_RULES[rule_id],
                })
                seen_rule_ids.add(rule_id)

    detected = bool(evidence)

    return {
        "rule_detected": detected,
        "attack_type": (
            "Server-Side Request Forgery (SSRF)" if detected else None
        ),
        "severity": "High" if detected else None,
        "confidence": 0.0,
        "evidence": evidence,
        "source": "security_rule",
    }
