import unittest

from Detection.sqli import detect_sqli


class SQLInjectionDetectionTests(unittest.TestCase):

    def test_normal_request_is_not_detected(self):
        event = {
            "path": "/search",
            "query": {
                "q": "laptop"
            },
            "body": {}
        }

        result = detect_sqli(event)

        self.assertFalse(result["rule_detected"])

    def test_union_select_is_detected(self):
        event = {
            "path": "/search",
            "query": {
                "q": "example UNION SELECT username FROM users"
            },
            "body": {}
        }

        result = detect_sqli(event)

        self.assertTrue(result["rule_detected"])
        self.assertEqual(result["attack_type"], "SQL Injection")
        self.assertIn("SQLI-001", [
            item["rule_id"] for item in result["evidence"]
        ])

    def test_insert_into_is_detected(self):
        event = {
            "path": "/search",
            "query": {
                "q": "INSERT INTO users"
            },
            "body": {}
        }

        result = detect_sqli(event)

        self.assertTrue(result["rule_detected"])

    def test_comment_without_sql_context_is_not_detected(self):
        event = {
            "path": "/search",
            "query": {
                "q": "hello-world--test"
            },
            "body": {}
        }

        result = detect_sqli(event)

        self.assertFalse(result["rule_detected"])

    def test_encoded_union_select_is_detected(self):
        event = {
            "path": "/search",
            "query": {
                "q": "example%20UNION%20SELECT%20username%20FROM%20users"
            },
            "body": {}
        }

        result = detect_sqli(event)

        self.assertTrue(result["rule_detected"])


if __name__ == "__main__":
    unittest.main()