
import unittest

from Detection.security_misconfiguration import (
    detect_security_misconfiguration,
)


class SecurityMisconfigurationTests(unittest.TestCase):

    def test_missing_security_headers_are_detected(self):
        result = detect_security_misconfiguration({
            "response": {
                "headers": {
                    "Content-Type": "text/html",
                },
                "body": "Welcome",
            },
        })

        self.assertTrue(result["rule_detected"])
        rule_ids = [item["rule_id"] for item in result["evidence"]]

        self.assertIn("MISCONFIG-001", rule_ids)
        self.assertIn("MISCONFIG-002", rule_ids)
        self.assertIn("MISCONFIG-003", rule_ids)

    def test_complete_security_headers_are_not_flagged(self):
        result = detect_security_misconfiguration({
            "response": {
                "headers": {
                    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                },
                "body": "Welcome",
            },
        })

        self.assertFalse(result["rule_detected"])

    def test_cookie_missing_secure_is_detected(self):
        result = detect_security_misconfiguration({
            "response": {
                "headers": {
                    "Set-Cookie": "session=abc; HttpOnly; Path=/",
                },
                "body": "",
            },
        })

        self.assertIn(
            "MISCONFIG-004",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_cookie_missing_httponly_is_detected(self):
        result = detect_security_misconfiguration({
            "response": {
                "headers": {
                    "Set-Cookie": "session=abc; Secure; Path=/",
                },
                "body": "",
            },
        })

        self.assertIn(
            "MISCONFIG-005",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_stack_trace_is_detected(self):
        result = detect_security_misconfiguration({
            "response": {
                "headers": {},
                "body": (
                    "Traceback (most recent call last):\n"
                    "  File \"app.py\", line 10, in handler\n"
                    "ValueError: invalid input"
                ),
            },
        })

        self.assertIn(
            "MISCONFIG-006",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_missing_response_is_not_treated_as_missing_headers(self):
        result = detect_security_misconfiguration({
            "path": "/login",
            "query": {},
        })

        self.assertFalse(result["rule_detected"])
        self.assertEqual(result["evidence"], [])

    def test_empty_response_is_checked(self):
        result = detect_security_misconfiguration({
            "response": {
                "headers": {},
                "body": "",
            },
        })

        self.assertTrue(result["rule_detected"])

    def test_invalid_event_type_is_rejected(self):
        with self.assertRaises(TypeError):
            detect_security_misconfiguration("not a dictionary")


if __name__ == "__main__":
    unittest.main()
