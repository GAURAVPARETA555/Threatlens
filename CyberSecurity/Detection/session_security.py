
from typing import Any


SESSION_SECURITY_RULES = {
    "SESSION-001": "Session identifier did not change after authentication",
    "SESSION-002": "Session was used after logout",
}


def _no_detection() -> dict:
    return {
        "rule_detected": False,
        "attack_type": None,
        "severity": None,
        "confidence": 0.0,
        "evidence": [],
        "source": "security_rule",
    }


def detect_session_security(event: dict) -> dict:
    """
    Detect explicit session-lifecycle security indicators.

    Expected optional fields:
      event["session"]["event_type"]: "authentication" or "request"
      event["session"]["session_id_before"]: prior session identifier
      event["session"]["session_id_after"]: resulting session identifier
      event["session"]["authenticated"]: whether authentication succeeded
      event["session"]["logged_out"]: whether the session was logged out
      event["session"]["used_after_logout"]: explicitly established reuse

    This detector relies on trustworthy session telemetry. It does not
    infer session fixation or hijacking from a session ID alone.
    """

    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")

    session: Any = event.get("session")

    if not isinstance(session, dict):
        return _no_detection()

    evidence = []

    event_type = session.get("event_type")
    authenticated = session.get("authenticated")
    before = session.get("session_id_before")
    after = session.get("session_id_after")

    if (
        isinstance(event_type, str)
        and event_type.strip().lower() == "authentication"
        and authenticated is True
        and isinstance(before, str)
        and isinstance(after, str)
        and before != after
    ):
        # A changed identifier is expected after successful authentication.
        pass
    elif (
        isinstance(event_type, str)
        and event_type.strip().lower() == "authentication"
        and authenticated is True
        and isinstance(before, str)
        and isinstance(after, str)
        and before == after
    ):
        evidence.append({
            "rule_id": "SESSION-001",
            "description": SESSION_SECURITY_RULES["SESSION-001"],
        })

    if session.get("used_after_logout") is True:
        evidence.append({
            "rule_id": "SESSION-002",
            "description": SESSION_SECURITY_RULES["SESSION-002"],
        })

    if not evidence:
        return _no_detection()

    return {
        "rule_detected": True,
        "attack_type": "Authentication & Session Security",
        "severity": "High",
        "confidence": 0.0,
        "evidence": evidence,
        "source": "security_rule",
    }
