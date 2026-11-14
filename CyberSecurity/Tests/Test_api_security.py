
import unittest

from Detection.api_security import detect_api_security


class APISecurityTests(unittest.TestCase):

    def test_rejected_authentication_is_detected(self):
        result = detect_api_security({
            "api_security": {
                "authentication_status": "rejected",
            },
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "API-001",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_invalid_api_key_is_detected(self):
        result = detect_api_security({
            "api_security": {
                "api_key_status": "invalid",
            },
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "API-002",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_rate_limit_enforcement_is_detected(self):
        result = detect_api_security({
            "api_security": {
                "rate_limited": True,
            },
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "API-003",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_multiple_indicators_are_preserved(self):
        result = detect_api_security({
            "api_security": {
                "authentication_status": "rejected",
                "api_key_status": "invalid",
                "rate_limited": True,
            },
        })

        rule_ids = [item["rule_id"] for item in result["evidence"]]

        self.assertEqual(
            set(rule_ids),
            {"API-001", "API-002", "API-003"},
        )

    def test_successful_api_request_is_not_flagged(self):
        result = detect_api_security({
            "api_security": {
                "authentication_status": "accepted",
                "api_key_status": "valid",
                "rate_limited": False,
            },
        })

        self.assertFalse(result["rule_detected"])

    def test_missing_api_security_context_is_not_flagged(self):
        result = detect_api_security({"path": "/api/users"})

        self.assertFalse(result["rule_detected"])
        self.assertEqual(result["evidence"], [])

    def test_empty_event_is_not_flagged(self):
        result = detect_api_security({})

        self.assertFalse(result["rule_detected"])

    def test_invalid_event_type_raises_error(self):
        with self.assertRaises(TypeError):
            detect_api_security("not a dictionary")


if __name__ == "__main__":
    unittest.main()
