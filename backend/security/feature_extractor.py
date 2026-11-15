import re
from datetime import timedelta
from urllib.parse import parse_qsl, unquote, urlsplit

from django.utils import timezone

from .models import SecurityEvent

# --- Set these to match ml/generate_dataset.py (step 2) -----------------------
# request_rate = events from this IP in the window / window  (per second)
RATE_WINDOW_SECONDS = 10
# failed logins counted over this window (300 s = same as Member 4's BRUTE-001)
FAILED_LOGIN_WINDOW_SECONDS = 300
# which characters count as "special"
SPECIAL_CHAR_PATTERN = re.compile(r"[^A-Za-z0-9\s]")
# raw_payload keys read by Member 4's brute-force rule (confirm in
# CyberSecurity/Tests/Test_brute_force.py)
EVENT_TYPE_KEY = "event_type"
OUTCOME_KEY = "outcome"
# ------------------------------------------------------------------------------


def _flatten_values(value, depth=0):
    """Yield every string inside nested dicts/lists (values only, never keys)."""
    if depth > 6:
        return
    if isinstance(value, dict):
        for item in value.values():
            yield from _flatten_values(item, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _flatten_values(item, depth + 1)
    elif value is not None:
        yield str(value)


def count_special_characters(endpoint, raw_payload):
    """Count special characters in the request data (query + body values)."""
    payload = raw_payload if isinstance(raw_payload, dict) else {}
    parts = [
        value
        for _, value in parse_qsl(urlsplit(endpoint or "").query, keep_blank_values=True)
    ]
    parts.extend(_flatten_values(payload.get("query")))
    parts.extend(_flatten_values(payload.get("body")))
    return len(SPECIAL_CHAR_PATTERN.findall(unquote(" ".join(parts))))


def compute_recent_failed_logins(source_ip, window_seconds=FAILED_LOGIN_WINDOW_SECONDS):
    cutoff = timezone.now() - timedelta(seconds=window_seconds)
    return SecurityEvent.objects.filter(
        source_ip=source_ip,
        timestamp__gte=cutoff,
        **{
            f"raw_payload__{EVENT_TYPE_KEY}": "authentication",
            f"raw_payload__{OUTCOME_KEY}": "failure",
        },
    ).count()


def compute_request_rate(source_ip, window_seconds=RATE_WINDOW_SECONDS):
    cutoff = timezone.now() - timedelta(seconds=window_seconds)
    count = SecurityEvent.objects.filter(
        source_ip=source_ip, timestamp__gte=cutoff
    ).count()
    return round(count / float(window_seconds), 2)


def enrich_event_features(event):
    """Fill the features that were not supplied (still 0). Supplied values stay."""
    updated = []
    if not event.special_char_count:
        event.special_char_count = count_special_characters(
            event.endpoint, event.raw_payload
        )
        updated.append("special_char_count")
    if not event.failed_login_count:
        event.failed_login_count = compute_recent_failed_logins(event.source_ip)
        updated.append("failed_login_count")
    if not event.request_rate:
        event.request_rate = compute_request_rate(event.source_ip)
        updated.append("request_rate")
    event.save(update_fields=updated)