import unittest

from backend.mock_ml import classify_telemetry


class MockMLTests(unittest.TestCase):
    def test_attack_families_have_deterministic_distinct_confidence(self):
        payloads = {
            "sql": {
                "endpoint": "/products",
                "raw_payload": {"query": {"q": "' UNION SELECT user FROM users --"}},
            },
            "xss": {
                "endpoint": "/comment",
                "raw_payload": {"body": {"comment": "<script>alert(1)</script>"}},
            },
            "path": {
                "endpoint": "/download",
                "raw_payload": {"query": {"file": "../../../../etc/passwd"}},
            },
            "command": {
                "endpoint": "/tools/run",
                "raw_payload": {"query": {"command": "id; whoami"}},
            },
        }

        results = {
            name: classify_telemetry(payload)
            for name, payload in payloads.items()
        }

        self.assertTrue(all(result["prediction"] == "malicious" for result in results.values()))
        self.assertEqual(
            len({result["confidence"] for result in results.values()}),
            len(results),
        )
        self.assertEqual(results, {
            name: classify_telemetry(payload)
            for name, payload in payloads.items()
        })

    def test_benign_traffic_has_low_confidence(self):
        result = classify_telemetry({
            "endpoint": "/search",
            "raw_payload": {"query": {"q": "how to use python"}},
            "request_rate": 2,
            "failed_logins": 0,
            "special_characters": 0,
        })

        self.assertEqual(result["prediction"], "benign")
        self.assertLess(result["confidence"], 0.25)
