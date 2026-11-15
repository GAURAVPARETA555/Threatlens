
import unittest
from datetime import datetime, timedelta, timezone

from Detection.brute_force import BruteForceDetector


class BruteForceDetectionTests(unittest.TestCase):

    def setUp(self):
        self.detector = BruteForceDetector(
            threshold=5,
            window_seconds=300,
        )
        self.start = datetime(
            2026, 10, 30, 10, 0, 0, tzinfo=timezone.utc
        )

    def make_event(self, seconds, outcome="failure"):
        return {
            "timestamp": (
                self.start + timedelta(seconds=seconds)
            ).isoformat(),
            "source_ip": "192.0.2.10",
            "event_type": "authentication",
            "outcome": outcome,
        }

    def test_fewer_than_threshold_is_not_detected(self):
        for seconds in (0, 10, 20, 30):
            result = self.detector.analyze_event(
                self.make_event(seconds)
            )

        self.assertFalse(result["rule_detected"])

    def test_threshold_failures_are_detected(self):
        for seconds in (0, 10, 20, 30):
            self.detector.analyze_event(self.make_event(seconds))

        result = self.detector.analyze_event(self.make_event(40))

        self.assertTrue(result["rule_detected"])
        self.assertEqual(result["attack_type"], "Brute Force")
        self.assertIn(
            "BRUTE-001",
            [item["rule_id"] for item in result["evidence"]],
        )

    def test_old_failures_expire_from_window(self):
        for seconds in (0, 10, 20, 30):
            self.detector.analyze_event(self.make_event(seconds))

        # The earlier attempts are now outside the five-minute window.
        result = self.detector.analyze_event(
            self.make_event(301)
        )

        self.assertFalse(result["rule_detected"])

    def test_successful_login_does_not_increment_failures(self):
        for seconds in (0, 10, 20, 30):
            self.detector.analyze_event(self.make_event(seconds))

        result = self.detector.analyze_event(
            self.make_event(40, outcome="success")
        )

        self.assertFalse(result["rule_detected"])

    def test_different_ip_has_separate_history(self):
        for seconds in (0, 10, 20, 30):
            self.detector.analyze_event(self.make_event(seconds))

        other_ip_event = self.make_event(40)
        other_ip_event["source_ip"] = "192.0.2.20"

        result = self.detector.analyze_event(other_ip_event)

        self.assertFalse(result["rule_detected"])

    def test_non_authentication_event_is_ignored(self):
        event = self.make_event(0)
        event["event_type"] = "page_view"

        result = self.detector.analyze_event(event)

        self.assertFalse(result["rule_detected"])

    def test_invalid_timestamp_is_rejected(self):
        event = self.make_event(0)
        event["timestamp"] = "not-a-timestamp"

        with self.assertRaises(ValueError):
            self.detector.analyze_event(event)

    def test_missing_source_ip_is_rejected(self):
        event = self.make_event(0)
        event["source_ip"] = ""

        with self.assertRaises(ValueError):
            self.detector.analyze_event(event)

    def test_invalid_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            BruteForceDetector(threshold=0)

    def test_naive_timestamp_is_rejected(self):
        event = self.make_event(0)
        event["timestamp"] = "2026-10-30T10:00:00"

        with self.assertRaises(ValueError):
            self.detector.analyze_event(event)

    def test_successful_login_resets_failure_count(self):
        # 4 failures recorded
        for seconds in (0, 10, 20, 30):
            self.detector.analyze_event(self.make_event(seconds))

        # Successful login resets the sequence
        success_result = self.detector.analyze_event(
            self.make_event(40, outcome="success")
        )
        self.assertFalse(success_result["rule_detected"])

        # 1 new failure after reset should NOT trigger threshold 5
        result = self.detector.analyze_event(self.make_event(50))
        self.assertFalse(result["rule_detected"])

    def test_successful_login_after_threshold_does_not_alert(self):
        # Trigger 5 failures
        for seconds in (0, 10, 20, 30, 40):
            self.detector.analyze_event(self.make_event(seconds))

        # A subsequent successful login must NEVER be flagged as brute force
        success_result = self.detector.analyze_event(
            self.make_event(50, outcome="success")
        )
        self.assertFalse(success_result["rule_detected"])
        self.assertIsNone(success_result["attack_type"])

    def test_lenient_mode_accepts_naive_timestamp(self):
        lenient_detector = BruteForceDetector(strict_mode=False)
        event = self.make_event(0)
        event["timestamp"] = "2026-10-30T10:00:00"

        # Should not raise ValueError in lenient mode
        result = lenient_detector.analyze_event(event)
        self.assertFalse(result["rule_detected"])

    def test_lenient_mode_handles_missing_or_malformed_timestamp(self):
        lenient_detector = BruteForceDetector(strict_mode=False)
        event = self.make_event(0)
        event["timestamp"] = "invalid-date"

        result = lenient_detector.analyze_event(event)
        self.assertFalse(result["rule_detected"])

        event["timestamp"] = None
        result2 = lenient_detector.analyze_event(event)
        self.assertFalse(result2["rule_detected"])

    def test_lenient_mode_handles_missing_outcome_safely(self):
        lenient_detector = BruteForceDetector(strict_mode=False)
        event = self.make_event(0)
        event["outcome"] = "unrelated_status"

        result = lenient_detector.analyze_event(event)
        self.assertFalse(result["rule_detected"])

    def test_multiple_users_supported_in_evidence(self):
        detector = BruteForceDetector(threshold=2, window_seconds=60)
        e1 = self.make_event(0)
        e1["username"] = "target_admin"
        e2 = self.make_event(10)
        e2["username"] = "target_admin"

        detector.analyze_event(e1)
        result = detector.analyze_event(e2)

        self.assertTrue(result["rule_detected"])
        self.assertEqual(result["evidence"][0].get("target_user"), "target_admin")

    def test_bounded_state_evicts_oldest_entries(self):
        # Cap detector at 2 tracked IPs
        detector = BruteForceDetector(
            threshold=5, window_seconds=300, max_tracked_entries=2
        )
        e1 = self.make_event(0)
        e1["source_ip"] = "192.0.2.1"
        detector.analyze_event(e1)

        e2 = self.make_event(10)
        e2["source_ip"] = "192.0.2.2"
        detector.analyze_event(e2)

        # Adding a 3rd IP should trigger eviction, keeping entries within bound
        e3 = self.make_event(20)
        e3["source_ip"] = "192.0.2.3"
        detector.analyze_event(e3)

        self.assertLessEqual(len(detector._failures), 2)

    def test_batch_historical_ingestion_with_invalid_timestamps_does_not_alert(self):
        """Verify that batch ingestion of logs with invalid timestamps cannot trigger false BRUTE-001."""
        detector = BruteForceDetector(
            threshold=5, window_seconds=300, strict_mode=False
        )

        invalid_timestamp_samples = [
            None,
            "not-an-iso-timestamp",
            "",
            "2026-99-99T99:99:99",
            1731327000,  # Numeric timestamp not supported as raw ISO
            [],
            {},
            "invalid_date_format",
            None,
            "corrupted_log_entry",
        ]

        for idx, bad_ts in enumerate(invalid_timestamp_samples):
            event = {
                "event_type": "authentication",
                "outcome": "failure",
                "source_ip": "198.51.100.99",
                "timestamp": bad_ts,
            }
            result = detector.analyze_event(event)
            # Must NEVER trigger an alert for unparseable timestamps
            self.assertFalse(result["rule_detected"])
            self.assertEqual(
                result.get("diagnostic"), "invalid_or_missing_timestamp"
            )

        # Confirm zero failures were recorded in the sliding window
        self.assertEqual(len(detector._failures["198.51.100.99"]), 0)

    def test_invalid_timestamps_do_not_contribute_to_window(self):
        """Confirm valid timestamps are tracked while interspersed invalid timestamps are ignored."""
        detector = BruteForceDetector(
            threshold=3, window_seconds=300, strict_mode=False
        )
        base_time = datetime(2026, 11, 11, 12, 0, 0, tzinfo=timezone.utc)

        # 1st valid failure
        r1 = detector.analyze_event({
            "event_type": "authentication",
            "outcome": "failure",
            "source_ip": "198.51.100.50",
            "timestamp": base_time.isoformat(),
        })
        self.assertFalse(r1["rule_detected"])
        self.assertEqual(len(detector._failures["198.51.100.50"]), 1)

        # Interspersed invalid failure events (must NOT increment window count)
        for bad_ts in (None, "bad-time", 12345):
            r_bad = detector.analyze_event({
                "event_type": "authentication",
                "outcome": "failure",
                "source_ip": "198.51.100.50",
                "timestamp": bad_ts,
            })
            self.assertFalse(r_bad["rule_detected"])
            self.assertEqual(len(detector._failures["198.51.100.50"]), 1)

        # 2nd valid failure
        r2 = detector.analyze_event({
            "event_type": "authentication",
            "outcome": "failure",
            "source_ip": "198.51.100.50",
            "timestamp": (base_time + timedelta(seconds=10)).isoformat(),
        })
        self.assertFalse(r2["rule_detected"])
        self.assertEqual(len(detector._failures["198.51.100.50"]), 2)

        # 3rd valid failure triggers threshold (3)
        r3 = detector.analyze_event({
            "event_type": "authentication",
            "outcome": "failure",
            "source_ip": "198.51.100.50",
            "timestamp": (base_time + timedelta(seconds=20)).isoformat(),
        })
        self.assertTrue(r3["rule_detected"])
        self.assertEqual(len(detector._failures["198.51.100.50"]), 3)

    def test_timezone_naive_timestamp_in_lenient_mode_contributes_safely(self):
        """Confirm timezone-naive timestamps are converted to UTC and function properly."""
        detector = BruteForceDetector(
            threshold=2, window_seconds=300, strict_mode=False
        )
        r1 = detector.analyze_event({
            "event_type": "authentication",
            "outcome": "failure",
            "source_ip": "198.51.100.25",
            "timestamp": "2026-11-11T12:00:00",  # Naive ISO string
        })
        self.assertFalse(r1["rule_detected"])

        r2 = detector.analyze_event({
            "event_type": "authentication",
            "outcome": "failure",
            "source_ip": "198.51.100.25",
            "timestamp": "2026-11-11T12:01:00",  # Naive ISO string within 300s
        })
        self.assertTrue(r2["rule_detected"])
        self.assertEqual(r2["attack_type"], "Brute Force")


if __name__ == "__main__":
    unittest.main()
