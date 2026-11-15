
import unittest

from Detection.command_injection import detect_command_injection


class CommandInjectionDetectionTests(unittest.TestCase):

    def test_normal_request_is_not_detected(self):
        result = detect_command_injection({
            "path": "/products",
            "query": {"search": "laptop"},
            "body": {},
        })

        self.assertFalse(result["rule_detected"])
        self.assertIsNone(result["attack_type"])
        self.assertEqual(result["evidence"], [])

    def test_command_chaining_pattern_is_detected(self):
        result = detect_command_injection({
            "path": "/search",
            "query": {"q": "item; whoami"},
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "CMDI-001",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_command_substitution_pattern_is_detected(self):
        result = detect_command_injection({
            "path": "/search",
            "query": {"q": "$(whoami)"},
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "CMDI-002",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_suspicious_command_pattern_is_detected(self):
        result = detect_command_injection({
            "path": "/search",
            "query": {"q": "whoami"},
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "CMDI-003",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_url_encoded_pattern_is_detected(self):
        result = detect_command_injection({
            "path": "/search",
            "query": {"q": "%24%28whoami%29"},
        })

        self.assertTrue(result["rule_detected"])

    def test_nested_request_data_is_supported(self):
        result = detect_command_injection({
            "path": "/search",
            "query": {},
            "body": {
                "filters": {
                    "value": "$(whoami)"
                }
            },
        })

        self.assertTrue(result["rule_detected"])

    def test_empty_request_is_not_detected(self):
        result = detect_command_injection({})

        self.assertFalse(result["rule_detected"])
        self.assertEqual(result["evidence"], [])

    def test_json_identifier_is_not_detected_as_command_injection(self):
        result = detect_command_injection({
            "path": "/api/users",
            "query": {},
            "body": {
                "id": 101,
                "username": "arnav",
            },
        })

        self.assertFalse(result["rule_detected"])
        self.assertIsNone(result["attack_type"])
        self.assertEqual(result["evidence"], [])

    def test_query_parameter_named_id_is_not_detected(self):
        result = detect_command_injection({
            "path": "/products",
            "query": {"id": "5"},
            "body": {},
        })

        self.assertFalse(result["rule_detected"])
        self.assertIsNone(result["attack_type"])
        self.assertEqual(result["evidence"], [])

    def test_nested_api_identifier_is_not_detected(self):
        result = detect_command_injection({
            "path": "/api/items",
            "query": {},
            "body": {
                "filter": {"id": "item-999"},
                "sort": "id",
            },
        })

        self.assertFalse(result["rule_detected"])

    def test_chained_id_command_is_detected(self):
        result = detect_command_injection({
            "path": "/search",
            "query": {"q": "search; id"},
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "CMDI-001",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_command_substitution_with_id_is_detected(self):
        result = detect_command_injection({
            "path": "/search",
            "query": {"q": "$(id)"},
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "CMDI-002",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_id_with_flag_is_detected(self):
        result = detect_command_injection({
            "path": "/search",
            "query": {"q": "id -u"},
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "CMDI-003",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_absolute_path_id_is_detected(self):
        result = detect_command_injection({
            "path": "/search",
            "query": {"q": "/usr/bin/id"},
        })

        self.assertTrue(result["rule_detected"])
        self.assertIn(
            "CMDI-003",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_invalid_event_type_is_rejected(self):
        with self.assertRaises(TypeError):
            detect_command_injection("not a dictionary")


if __name__ == "__main__":
    unittest.main()
