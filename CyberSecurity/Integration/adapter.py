"""
ThreatLens CyberSecurity Backend Integration Adapter.

Provides a clean, transport-independent bridge between the standalone
Detection engine (Member 4) and the Django REST Framework backend (Member 1).
"""

from typing import Any

from Detection.engine import analyze_event
from Integration.exceptions import (
    ConfidencePolicyError,
    EventValidationError,
)
from Integration.serializers import (
    map_attack_name_to_backend,
    normalize_severity_to_backend,
    select_primary_attack_type,
    serialize_evidence_to_text,
)


class CyberSecurityAdapter:
    """
    Adapter converting raw security events into Django-ready payloads.

    Features:
    - Input event validation.
    - Deterministic primary attack mapping.
    - Textual evidence serialization matching DRF serializers.CharField.
    - Severity normalization matching Django model choices ('low', 'medium', 'high', 'critical').
    - Configurable confidence policy preventing uncalibrated float fabrication.
    - Integer event_id enforcement matching Django database primary keys.
    """

    def __init__(
        self,
        strict_confidence: bool = False,
        evidence_format: str = "text",
        map_attack_aliases: bool = True,
    ) -> None:
        self.strict_confidence = strict_confidence
        self.evidence_format = evidence_format
        self.map_attack_aliases = map_attack_aliases

    def validate_event(self, event: Any) -> None:
        """Validate that incoming event is a dictionary."""
        if not isinstance(event, dict):
            raise EventValidationError("Event must be a dictionary")

    def validate_event_id(
        self, event: dict, require_id: bool = True
    ) -> int | None:
        """Validate that event_id is a valid positive integer matching Django SecurityEvent.id."""
        event_id = event.get("event_id")
        if event_id is None:
            if require_id:
                raise EventValidationError(
                    "Missing 'event_id': backend integration requires an integer foreign key referencing SecurityEvent.id"
                )
            return None

        try:
            val = int(event_id)
            if val < 1:
                raise ValueError
            return val
        except (ValueError, TypeError) as exc:
            raise EventValidationError(
                f"Invalid 'event_id' ({event_id}): must be a positive integer matching SecurityEvent.id"
            ) from exc

    def process_event(
        self,
        event: dict,
        require_event_id: bool = True,
    ) -> dict[str, Any]:
        """
        Run the detection engine and format the result into Member 1's backend payload.

        Returns a dictionary directly compatible with DetectionAnalyzeSerializer:
        {
            "event_id": 1,
            "rule_detected": True,
            "rule_confidence": 0.0,
            "attack_type": "SQL Injection",
            "evidence": "[SQLI-001] Suspicious SQL keyword combination",
            "severity": "high",
            "canonical_result": { ... },
        }
        """
        self.validate_event(event)
        event_id = self.validate_event_id(event, require_id=require_event_id)

        # Execute the core detection engine without modifying the input event
        raw_result = analyze_event(event)

        # Enforce confidence policy
        if (
            self.strict_confidence
            and raw_result.get("confidence_status") == "uncalibrated"
        ):
            raise ConfidencePolicyError(
                "Uncalibrated rule confidence cannot be serialized as a verified float under strict confidence policy."
            )

        # Backend expects float between 0 and 1
        rule_confidence = raw_result.get("rule_confidence")
        if rule_confidence is None:
            rule_confidence = 0.0

        # Handle attack type
        attack_types = raw_result.get("attack_types", [])
        primary_attack = select_primary_attack_type(attack_types)
        if self.map_attack_aliases and primary_attack:
            backend_attack_type = map_attack_name_to_backend(primary_attack)
        else:
            backend_attack_type = primary_attack

        # Handle evidence serialization
        evidence_list = raw_result.get("evidence", [])
        evidence_str = serialize_evidence_to_text(evidence_list)

        # Handle severity normalization
        backend_severity = normalize_severity_to_backend(
            raw_result.get("severity")
        )

        return {
            "event_id": event_id,
            "rule_detected": bool(raw_result.get("rule_detected")),
            "rule_confidence": float(rule_confidence),
            "attack_type": backend_attack_type,
            "evidence": evidence_str,
            "severity": backend_severity,
            "canonical_result": raw_result,
        }


# Global default adapter instance for one-line invocations
DEFAULT_ADAPTER = CyberSecurityAdapter(strict_confidence=False)


def evaluate_for_backend(
    event: dict, require_event_id: bool = True, **kwargs
) -> dict[str, Any]:
    """
    Convenience function for Member 1 to evaluate an event and obtain a Django-ready payload.

    Example inside Django views.py:
        from Integration.adapter import evaluate_for_backend
        detection_payload = evaluate_for_backend(event_dict)
    """
    adapter = CyberSecurityAdapter(**kwargs) if kwargs else DEFAULT_ADAPTER
    return adapter.process_event(event, require_event_id=require_event_id)

