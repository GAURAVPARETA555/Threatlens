import logging
from datetime import timezone
from urllib.parse import parse_qs, urlsplit

from Integration import evaluate_for_backend

logger = logging.getLogger(__name__)


def build_detection_event(event):
    """
    Convert a SecurityEvent database row into the dictionary
    that Member 4's detection engine expects.
    """

    # Everything extra (query, body, response, session, authorization,
    # api_security ...) is read from raw_payload.
    detection_event = dict(event.raw_payload or {})

    # If the endpoint contains a query string (/search?q=abc), split it out.
    parts = urlsplit(event.endpoint or "")

    if "query" not in detection_event and parts.query:
        detection_event["query"] = {
            key: values[0] if len(values) == 1 else values
            for key, values in parse_qs(parts.query).items()
        }

    # Model columns always win over anything inside raw_payload.
    detection_event["event_id"] = event.id
    detection_event["source_ip"] = event.source_ip
    detection_event["timestamp"] = (
        event.timestamp.astimezone(timezone.utc).isoformat()
    )
    detection_event["path"] = parts.path or event.endpoint
    detection_event.setdefault("event_type", "http_request")

    return detection_event


def run_rules(event):
    """
    Run Member 4's rule engine on one SecurityEvent.
    Returns a simple dict used by DetectionAnalyzeView.
    """

    result = evaluate_for_backend(build_detection_event(event))

    # Detector crashes are isolated by the engine, so log them here.
    canonical = result.get("canonical_result") or {}
    for error in canonical.get("errors", []):
        logger.warning(
            "Detector error on event %s: %s", event.id, error
        )

    return {
        "rule_detected": bool(result.get("rule_detected", False)),
        # Member 4 reports 0.0 on purpose (uncalibrated confidence).
        "rule_confidence": float(result.get("rule_confidence", 0.0)),
        "attack_type": result.get("attack_type") or "",
        "evidence": result.get("evidence") or "",
        "severity": result.get("severity") or "low",
    }