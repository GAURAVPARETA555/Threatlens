
import unittest

from datetime import datetime, timedelta, timezone
from Detection.engine import analyze_event

from Detection.brute_force import BRUTE_FORCE_DETECTOR

class DetectionEngineTests(unittest.TestCase):

    def test_sqli_event_is_detected(self):
        event = {
            "path": "/search",
            "query": {
                "q": "test UNION SELECT username FROM users"
            },
            "body": {},
        }

        result = analyze_event(event)

        self.assertTrue(result["rule_detected"])
        self.assertEqual(result["attack_type"], "SQL Injection")
        self.assertEqual(result["source"], "security_rule")

    def test_xss_event_is_detected(self):
        event = {
            "path": "/comment",
            "query": {},
            "body": {
                "comment": "<script>alert(1)</script>"
            },
        }

        result = analyze_event(event)

        self.assertTrue(result["rule_detected"])
        self.assertEqual(
            result["attack_type"],
            "Cross-Site Scripting (XSS)",
        )
        self.assertIn(
            "XSS-001",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_normal_event_is_not_detected(self):
        event = {
            "path": "/search",
            "query": {"q": "laptop"},
            "body": {},
        }

        result = analyze_event(event)

        self.assertFalse(result["rule_detected"])
        self.assertIsNone(result["attack_type"])
        self.assertEqual(result["evidence"], [])

    def test_multiple_detectors_preserve_all_findings(self):
        event = {
            "path": "/search",
            "query": {
                "q": "UNION SELECT username FROM users"
            },
            "body": {
                "comment": "<script>alert(1)</script>"
            },
        }

        result = analyze_event(event)

        self.assertTrue(result["rule_detected"])
        self.assertIsInstance(result["attack_type"], list)
        self.assertIn("SQL Injection", result["attack_type"])
        self.assertIn(
            "Cross-Site Scripting (XSS)",
            result["attack_type"],
        )

        detected_rule_ids = {
            item["rule_id"] for item in result["evidence"]
        }
        self.assertIn("SQLI-001", detected_rule_ids)
        self.assertIn("XSS-001", detected_rule_ids)

    def test_invalid_event_type_raises_error(self):
        with self.assertRaises(TypeError):
            analyze_event("not a dictionary")

    def test_brute_force_is_detected_through_engine(self):
        BRUTE_FORCE_DETECTOR.reset()

        start = datetime(
            2026, 10, 30, 10, 0, tzinfo=timezone.utc
        )

        for attempt in range(5):
            event = {
                "event_type": "authentication",
                "outcome": "failure",
                "source_ip": "192.0.2.50",
                "timestamp": (
                    start + timedelta(seconds=attempt * 10)
                ).isoformat(),
            }

            result = analyze_event(event)

        self.assertTrue(result["rule_detected"])
        self.assertEqual(result["attack_type"], "Brute Force")
        self.assertIn(
            "BRUTE-001",
            [item["rule_id"] for item in result["evidence"]],
        )

        BRUTE_FORCE_DETECTOR.reset()
        
    def test_path_traversal_detection(self):
        event = {
            "path": "/download",
            "query": {
                "file": "../../private/data.txt"
            },
            "body": {},
        }

        result = analyze_event(event)

        self.assertTrue(result["rule_detected"])
        self.assertIn("Path Traversal", result["attack_type"])
        self.assertIn(
            "PTRAV-001",
            [item["rule_id"] for item in result["evidence"]],
        )
        
    def test_command_injection_detection(self):
        event = {
            "path": "/search",
            "query": {"q": "item; whoami"},
            "body": {},
        }

        result = analyze_event(event)

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "OS Command Injection",
            result["attack_type"],
        )
        self.assertIn(
            "CMDI-001",
            [item["rule_id"] for item in result["evidence"]],
        )
        
    def test_ssrf_detection(self):
        event = {
            "path": "/preview",
            "query": {
                "url": "http://127.0.0.1/admin"
            },
            "body": {},
        }

        result = analyze_event(event)

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "Server-Side Request Forgery (SSRF)",
            result["attack_type"],
        )
        self.assertIn(
            "SSRF-001",
            [item["rule_id"] for item in result["evidence"]],
        )        

    def test_security_misconfiguration_detection(self):
        event = {
            "path": "/login",
            "response": {
                "headers": {
                    "Content-Type": "text/html",
                },
                "body": "Welcome",
            },
        }

        result = analyze_event(event)

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "Security Misconfiguration",
            result["attack_type"],
        )
        self.assertIn(
            "MISCONFIG-001",
            [item["rule_id"] for item in result["evidence"]],
        )        

    def test_idor_detection(self):
        event = {
            "path": "/users/123/documents/456",
            "authorization": {
                "decision": "deny",
                "reason": "ownership_mismatch",
            },
        }

        result = analyze_event(event)

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "Broken Access Control / IDOR Indicator",
            result["attack_type"],
        )

        rule_ids = [item["rule_id"] for item in result["evidence"]]
        self.assertIn("IDOR-001", rule_ids)
        self.assertIn("IDOR-002", rule_ids)

    def test_session_security_detection(self):
        event = {
            "path": "/login",
            "session": {
                "event_type": "authentication",
                "authenticated": True,
                "session_id_before": "session-old",
                "session_id_after": "session-old",
            },
        }

        result = analyze_event(event)

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "Authentication & Session Security",
            result["attack_type"],
        )
        self.assertIn(
            "SESSION-001",
            [item["rule_id"] for item in result["evidence"]],
        )        
        
    def test_api_security_detection(self):
        event = {
            "path": "/api/users",
            "api_security": {
                "authentication_status": "rejected",
            },
        }

        result = analyze_event(event)

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "API Security Indicator",
            result["attack_type"],
        )
        self.assertIn(
            "API-001",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_detector_exception_is_isolated_and_other_detectors_execute(self):
        from Detection.engine import register_detector, unregister_detector

        def faulty_detector(event):
            raise RuntimeError("Faulty detector simulation error")

        register_detector(faulty_detector)
        try:
            event = {
                "path": "/comment",
                "body": {"comment": "<script>alert(1)</script>"},
            }
            result = analyze_event(event)

            # Faulty detector error must be captured in metadata
            self.assertTrue(len(result["errors"]) >= 1)
            error_entry = next(
                (e for e in result["errors"] if e["detector"] == "faulty_detector"),
                None,
            )
            self.assertIsNotNone(error_entry)
            self.assertIn("Faulty detector simulation error", error_entry["error"])

            # XSS detector should still have executed and detected the attack
            self.assertTrue(result["rule_detected"])
            self.assertEqual(result["attack_type"], "Cross-Site Scripting (XSS)")
        finally:
            unregister_detector(faulty_detector)

    def test_event_id_is_preserved_when_supplied(self):
        event = {
            "event_id": "test-uuid-12345",
            "path": "/search",
            "query": {"q": "laptop"},
        }
        result = analyze_event(event)
        self.assertEqual(result["event_id"], "test-uuid-12345")

    def test_deterministic_severity_aggregation_for_medium_findings(self):
        event = {
            "path": "/api/users",
            "api_security": {
                "authentication_status": "rejected",
            },
        }
        result = analyze_event(event)
        self.assertEqual(result["severity"], "Medium")

    def test_invalid_detector_output_handled_safely(self):
        from Detection.engine import register_detector, unregister_detector

        def malformed_detector(event):
            return "not-a-dict"

        register_detector(malformed_detector)
        try:
            event = {"path": "/search", "query": {"q": "laptop"}}
            result = analyze_event(event)

            self.assertTrue(len(result["errors"]) >= 1)
            error_entry = next(
                (e for e in result["errors"] if e["detector"] == "malformed_detector"),
                None,
            )
            self.assertIsNotNone(error_entry)
            self.assertIn("invalid result structure", error_entry["error"])
        finally:
            unregister_detector(malformed_detector)

    def test_detector_registry_functions(self):
        from Detection.engine import (
            get_registered_detectors,
            register_detector,
            unregister_detector,
        )

        def dummy_detector(event):
            return {"rule_detected": False}

        initial_count = len(get_registered_detectors())
        register_detector(dummy_detector)
        self.assertEqual(len(get_registered_detectors()), initial_count + 1)

        unregister_detector(dummy_detector)
        self.assertEqual(len(get_registered_detectors()), initial_count)


if __name__ == "__main__":
    unittest.main()
