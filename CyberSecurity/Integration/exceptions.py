"""
Custom exceptions for the ThreatLens CyberSecurity backend integration layer.
"""


class IntegrationError(Exception):
    """Base exception for all integration and adapter failures."""


class EventValidationError(IntegrationError):
    """Raised when an incoming event fails canonical schema validation."""


class SerializationError(IntegrationError):
    """Raised when a detection result cannot be serialized for backend transport."""


class ConfidencePolicyError(IntegrationError):
    """Raised when uncalibrated confidence cannot be serialized under a strict confidence policy."""


class SeverityMappingError(IntegrationError):
    """Raised when an internal severity value cannot be mapped to a backend choice."""

