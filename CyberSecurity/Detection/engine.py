
from typing import Any, Callable

from Detection.api_security import detect_api_security
from Detection.brute_force import detect_brute_force
from Detection.command_injection import detect_command_injection
from Detection.idor import detect_idor
from Detection.path_traversal import detect_path_traversal
from Detection.security_misconfiguration import (
    detect_security_misconfiguration,
)
from Detection.session_security import detect_session_security
from Detection.sqli import detect_sqli
from Detection.ssrf import detect_ssrf
from Detection.xss import detect_xss


DETECTORS: list[Callable[[dict], dict]] = [
    detect_sqli,
    detect_xss,
    detect_brute_force,
    detect_path_traversal,
    detect_command_injection,
    detect_ssrf,
    detect_security_misconfiguration,
    detect_idor,
    detect_session_security,
    detect_api_security,
]

SEVERITY_WEIGHTS: dict[str, int] = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
}


def register_detector(detector: Callable[[dict], dict]) -> None:
    """Register a new detection function in the engine registry."""
    if detector not in DETECTORS:
        DETECTORS.append(detector)


def unregister_detector(detector: Callable[[dict], dict]) -> None:
    """Unregister a detection function from the engine registry."""
    if detector in DETECTORS:
        DETECTORS.remove(detector)


def get_registered_detectors() -> list[Callable[[dict], dict]]:
    """Return a copy of all currently registered detectors."""
    return list(DETECTORS)


def _aggregate_severity(results: list[dict]) -> str | None:
    """Determine highest severity deterministically from detector findings."""
    severities = [
        r.get("severity")
        for r in results
        if isinstance(r.get("severity"), str)
    ]
    if not severities:
        return None
    return max(severities, key=lambda s: SEVERITY_WEIGHTS.get(s, 0))


def analyze_event(event: dict) -> dict:
    """
    Run all registered security detectors against one event.

    Features:
    - Exception isolation: failure in one detector does not stop others.
    - Detector failure tracking in structured 'errors' metadata.
    - Full backward compatibility with existing backend contracts.
    - Deterministic severity aggregation.
    - Event ID correlation preservation.
    """
    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")

    event_id = event.get("event_id")
    results = []
    detector_results = []
    errors = []

    for detector in DETECTORS:
        detector_name = getattr(detector, "__name__", str(detector))
        try:
            result = detector(event)
            if not isinstance(result, dict) or "rule_detected" not in result:
                errors.append({
                    "detector": detector_name,
                    "error": "Detector returned an invalid result structure",
                })
                continue

            detector_results.append(result)
            if result.get("rule_detected"):
                results.append(result)
        except Exception as exc:
            errors.append({
                "detector": detector_name,
                "error": str(exc),
            })

    output: dict[str, Any] = {
        "event_id": event_id,
        "rule_detected": len(results) > 0,
        "rule_confidence": 0.0,
        "confidence": 0.0,  # Maintained for legacy compatibility
        "confidence_status": "uncalibrated",
        "source": "security_rule",
        "detector_results": detector_results,
        "errors": errors,
    }

    if not results:
        output.update({
            "attack_type": None,
            "attack_types": [],
            "severity": None,
            "evidence": [],
        })
        return output

    attack_types: list[str] = list(dict.fromkeys(
        item
        for result in results
        for item in (
            [result["attack_type"]]
            if isinstance(result.get("attack_type"), str)
            else result.get("attack_type") or []
        )
    ))

    evidence: list[dict] = [
        item
        for result in results
        for item in result.get("evidence", [])
    ]

    severity = _aggregate_severity(results)

    # Legacy compatibility: scalar string if single attack type, list if multiple
    legacy_attack_type = (
        attack_types[0] if len(attack_types) == 1 else attack_types
    )

    output.update({
        "attack_type": legacy_attack_type,
        "attack_types": attack_types,
        "severity": severity,
        "evidence": evidence,
    })

    return output
