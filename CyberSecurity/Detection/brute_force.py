
from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import Lock
from typing import Any


DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_SECONDS = 300
DEFAULT_MAX_TRACKED_ENTRIES = 10_000


class BruteForceDetector:
    """
    Detect repeated failed authentication attempts per source IP.

    State is maintained in-process within a bounded sliding time window.
    Process-local state is thread-safe via a standard lock, but is isolated
    per worker process in multi-process deployments.
    """

    def __init__(
        self,
        threshold: int = DEFAULT_THRESHOLD,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        max_tracked_entries: int = DEFAULT_MAX_TRACKED_ENTRIES,
        strict_mode: bool = True,
    ) -> None:
        if threshold < 1:
            raise ValueError("threshold must be at least 1")
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")
        if max_tracked_entries < 1:
            raise ValueError("max_tracked_entries must be at least 1")

        self.threshold = threshold
        self.window_seconds = window_seconds
        self.max_tracked_entries = max_tracked_entries
        self.strict_mode = strict_mode
        self._failures: dict[str, deque[datetime]] = defaultdict(deque)
        self._lock = Lock()

    def reset(self) -> None:
        """Clear recorded history; useful for tests and controlled resets."""
        with self._lock:
            self._failures.clear()

    @staticmethod
    def _parse_timestamp(value: Any, strict: bool = True) -> datetime | None:
        """
        Parse and validate ISO 8601 or datetime objects into UTC datetime.

        In strict mode:
        - Timezone-naive timestamps, malformed formats, or missing timestamps raise ValueError.

        In lenient mode:
        - Timezone-naive timestamps are assumed UTC.
        - Missing, None, malformed, or invalid type timestamps return None so they
          do not corrupt or falsely inflate sliding time windows.
        """
        if value is None:
            if strict:
                raise ValueError(
                    "timestamp must be an ISO 8601 string or datetime"
                )
            return None

        if isinstance(value, datetime):
            timestamp = value
        elif isinstance(value, str):
            if not value.strip():
                if strict:
                    raise ValueError(
                        "timestamp must be an ISO 8601 string or datetime"
                    )
                return None
            try:
                timestamp = datetime.fromisoformat(
                    value.replace("Z", "+00:00")
                )
            except (ValueError, TypeError) as exc:
                if strict:
                    raise ValueError(
                        "timestamp must be valid ISO 8601"
                    ) from exc
                return None
        else:
            if strict:
                raise ValueError(
                    "timestamp must be an ISO 8601 string or datetime"
                )
            return None

        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            if strict:
                raise ValueError("timestamp must include a timezone")
            return timestamp.replace(tzinfo=timezone.utc)

        return timestamp.astimezone(timezone.utc)

    def _prune_stale_entries(self, current_cutoff: float) -> None:
        """Prune expired failure records and enforce bounded memory limits."""
        stale_keys = [
            ip
            for ip, failures in self._failures.items()
            if not failures or failures[-1].timestamp() < current_cutoff
        ]
        for ip in stale_keys:
            self._failures.pop(ip, None)

        if len(self._failures) > self.max_tracked_entries:
            # Evict keys with the oldest failure records
            sorted_keys = sorted(
                self._failures.keys(),
                key=lambda k: self._failures[k][0].timestamp()
                if self._failures[k]
                else 0,
            )
            to_remove = len(self._failures) - self.max_tracked_entries
            for key in sorted_keys[:to_remove]:
                self._failures.pop(key, None)

    def analyze_event(self, event: dict) -> dict:
        """
        Evaluate an authentication event against brute-force threshold criteria.

        Counts only 'failure' outcomes with valid timestamps. A 'success' outcome
        clears recorded failures for the source IP and returns no detection.
        Invalid or missing timestamps are excluded from the sliding window.
        """
        if not isinstance(event, dict):
            raise TypeError("event must be a dictionary")

        if event.get("event_type") != "authentication":
            return self._no_detection()

        outcome = event.get("outcome")
        if not isinstance(outcome, str) or outcome.lower() not in {
            "failure",
            "success",
        }:
            if self.strict_mode:
                raise ValueError(
                    "authentication outcome must be 'failure' or 'success'"
                )
            return self._no_detection(diagnostic="invalid_or_missing_outcome")

        outcome = outcome.lower()

        source_ip = event.get("source_ip")
        if not isinstance(source_ip, str) or not source_ip.strip():
            if self.strict_mode:
                raise ValueError("source_ip must be a non-empty string")
            return self._no_detection(diagnostic="invalid_or_missing_source_ip")

        source_ip = source_ip.strip()
        timestamp = self._parse_timestamp(
            event.get("timestamp"), strict=self.strict_mode
        )

        with self._lock:
            if outcome == "success":
                # Successful authentication resets the failure sequence for this source IP
                self._failures.pop(source_ip, None)
                return self._no_detection()

            # Events lacking a valid timestamp cannot contribute to the sliding time window
            if timestamp is None:
                return self._no_detection(
                    diagnostic="invalid_or_missing_timestamp"
                )

            cutoff_seconds = timestamp.timestamp() - self.window_seconds

            failures = self._failures[source_ip]

            while (
                failures
                and failures[0].timestamp() < cutoff_seconds
            ):
                failures.popleft()

            failures.append(timestamp)
            count = len(failures)
            detected = count >= self.threshold

            if not failures:
                self._failures.pop(source_ip, None)

            # Enforce memory bounds if total tracked entries exceed limit
            if len(self._failures) > self.max_tracked_entries:
                self._prune_stale_entries(cutoff_seconds)

        if not detected:
            return self._no_detection()

        target_user = event.get("username") or event.get("user")
        evidence_entry = {
            "rule_id": "BRUTE-001",
            "description": (
                f"{count} failed authentication attempts from "
                f"the same source within "
                f"{self.window_seconds} seconds"
            ),
        }
        if target_user:
            evidence_entry["target_user"] = str(target_user)

        return {
            "rule_detected": True,
            "attack_type": "Brute Force",
            "severity": "High",
            "confidence": 0.0,
            "evidence": [evidence_entry],
            "source": "security_rule",
        }

    @staticmethod
    def _no_detection(diagnostic: str | None = None) -> dict:
        result: dict[str, Any] = {
            "rule_detected": False,
            "attack_type": None,
            "severity": None,
            "confidence": 0.0,
            "evidence": [],
            "source": "security_rule",
        }
        if diagnostic:
            result["diagnostic"] = diagnostic
        return result


# One shared instance preserves history between engine calls
# within this Python process. Lenient mode ensures engine stability
# and prevents malformed timestamps from causing false positive spikes.
BRUTE_FORCE_DETECTOR = BruteForceDetector(strict_mode=False)


def detect_brute_force(event: dict) -> dict:
    """Engine-compatible interface for stateful brute-force detection."""
    return BRUTE_FORCE_DETECTOR.analyze_event(event)
