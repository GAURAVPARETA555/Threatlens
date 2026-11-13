"""
ThreatLens CyberSecurity Integration Package.

Provides adapter interfaces for backend data transport and schema normalization.
"""

from Integration.adapter import (
    CyberSecurityAdapter,
    DEFAULT_ADAPTER,
    evaluate_for_backend,
)
from Integration.exceptions import (
    ConfidencePolicyError,
    EventValidationError,
    IntegrationError,
    SerializationError,
    SeverityMappingError,
)
from Integration.schemas import (
    ATTACK_NAME_ALIASES,
    ATTACK_PRIORITY,
    CANONICAL_EVENT_FIELDS,
    SEVERITY_BACKEND_MAP,
)
from Integration.serializers import (
    map_attack_name_to_backend,
    normalize_severity_to_backend,
    select_primary_attack_type,
    serialize_evidence_to_json,
    serialize_evidence_to_text,
)

__all__ = [
    "CyberSecurityAdapter",
    "DEFAULT_ADAPTER",
    "evaluate_for_backend",
    "IntegrationError",
    "EventValidationError",
    "SerializationError",
    "ConfidencePolicyError",
    "SeverityMappingError",
    "CANONICAL_EVENT_FIELDS",
    "SEVERITY_BACKEND_MAP",
    "ATTACK_PRIORITY",
    "ATTACK_NAME_ALIASES",
    "serialize_evidence_to_text",
    "serialize_evidence_to_json",
    "select_primary_attack_type",
    "map_attack_name_to_backend",
    "normalize_severity_to_backend",
]

