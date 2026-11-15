"""
Tests for the ThreatLens CyberSecurity backend integration adapter.
"""

import unittest

from Integration import (
    ConfidencePolicyError,
    CyberSecurityAdapter,
    EventValidationError,
    evaluate_for_backend,
    serialize_evidence_to_json,
    serialize_evidence_to_text,
)


class IntegrationAdapterTests(unittest.TestCase):

    def setUp(self):
        self.adapter = CyberSecurityAdapter(strict_confidence=False)

    def test_adapter_valid_single_sqli_event(self):
        event = {
            "event_id": 42,
            "path": "/search",
            "query": {"q": "UNION SELECT username FROM users"},
            "body": {},
        }
        result = self.adapter.process_event(event)

        self.assertEqual(result["event_id"], 42)
        self.assertTrue(result["rule_detected"])
        self.assertEqual(result["rule_confidence"], 0.0)
        self.assertEqual(result["attack_type"], "SQL Injection")
        self.assertEqual(result["severity"], "high")
        self.assertIsInstance(result["evidence"], str)
        self.assertIn("SQLI-001", result["evidence"])

    def test_adapter_multi_attack_primary_selection_and_evidence(self):
        event = {
            "event_id": 99,
            "path": "/search",
            "query": {"q": "UNION SELECT username FROM users"},
            "body": {"comment": "<script>alert(1)</script>"},
        }
        result = self.adapter.process_event(event)

        self.assertEqual(result["event_id"], 99)
        self.assertTrue(result["rule_detected"])
        # SQL Injection has higher precedence than XSS in ATTACK_PRIORITY
        self.assertEqual(result["attack_type"], "SQL Injection")
        self.assertEqual(result["severity"], "high")
        # Evidence string combines all findings
        self.assertIn("SQLI-001", result["evidence"])
        self.assertIn("XSS-001", result["evidence"])
        # Canonical rich result preserves full list
        self.assertEqual(
            set(result["canonical_result"]["attack_types"]),
            {"SQL Injection", "Cross-Site Scripting (XSS)"},
        )

    def test_adapter_clean_event_produces_backend_safe_defaults(self):
        event = {
            "event_id": 1,
            "path": "/products",
            "query": {"category": "books"},
            "body": {},
        }
        result = self.adapter.process_event(event)

        self.assertEqual(result["event_id"], 1)
        self.assertFalse(result["rule_detected"])
        self.assertEqual(result["rule_confidence"], 0.0)
        self.assertEqual(result["attack_type"], "")
        self.assertEqual(result["severity"], "low")
        self.assertEqual(result["evidence"], "")

    def test_adapter_event_id_validation(self):
        # Missing event_id when required
        with self.assertRaises(EventValidationError):
            self.adapter.process_event({"path": "/home"}, require_event_id=True)

        # String integer is safely cast to integer
        res = self.adapter.process_event(
            {"event_id": "105", "path": "/home"}, require_event_id=True
        )
        self.assertEqual(res["event_id"], 105)

        # Non-numeric string raises validation error
        with self.assertRaises(EventValidationError):
            self.adapter.process_event(
                {"event_id": "uuid-not-an-int", "path": "/home"},
                require_event_id=True,
            )

        # Negative or zero integer raises validation error
        with self.assertRaises(EventValidationError):
            self.adapter.process_event(
                {"event_id": -5, "path": "/home"}, require_event_id=True
            )

        # Optional event_id when require_event_id=False
        res_opt = self.adapter.process_event(
            {"path": "/home"}, require_event_id=False
        )
        self.assertIsNone(res_opt["event_id"])

    def test_adapter_strict_confidence_policy_raises_error(self):
        strict_adapter = CyberSecurityAdapter(strict_confidence=True)
        event = {
            "event_id": 1,
            "path": "/search",
            "query": {"q": "UNION SELECT username FROM users"},
        }
        with self.assertRaises(ConfidencePolicyError):
            strict_adapter.process_event(event)

    def test_adapter_non_dict_event_raises_validation_error(self):
        with self.assertRaises(EventValidationError):
            self.adapter.process_event("invalid-non-dict")

    def test_adapter_input_event_is_not_mutated(self):
        event = {
            "event_id": 77,
            "path": "/test",
            "query": {"q": "sample"},
            "body": {"key": "val"},
        }
        original_copy = dict(event)
        self.adapter.process_event(event)
        self.assertEqual(event, original_copy)

    def test_evaluate_for_backend_convenience_function(self):
        event = {
            "event_id": 12,
            "path": "/search",
            "query": {"q": "item; whoami"},
        }
        result = evaluate_for_backend(event)
        self.assertEqual(result["event_id"], 12)
        self.assertTrue(result["rule_detected"])
        self.assertEqual(result["attack_type"], "Command Injection")
        self.assertEqual(result["severity"], "high")

    def test_evidence_serialization_helpers(self):
        evidence_data = [
            {"rule_id": "PTRAV-001", "description": "Traversal sequence"},
            {
                "rule_id": "PTRAV-003",
                "description": "Sensitive file",
                "detail": "/etc/passwd",
            },
        ]
        text_out = serialize_evidence_to_text(evidence_data)
        self.assertIn("[PTRAV-001] Traversal sequence", text_out)
        self.assertIn("[PTRAV-003] Sensitive file (/etc/passwd)", text_out)

        json_out = serialize_evidence_to_json(evidence_data)
        self.assertIn('"rule_id": "PTRAV-001"', json_out)


if __name__ == "__main__":
    unittest.main()

