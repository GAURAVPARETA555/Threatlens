from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re
from urllib.parse import unquote


def _flatten(value):
    if isinstance(value, dict):
        return " ".join(
            f"{_flatten(key)} {_flatten(item)}"
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return " ".join(_flatten(item) for item in value)
    return str(value or "")


def classify_telemetry(payload):
    """Deterministic local classifier for development and demonstrations."""
    text = unquote(
        " ".join(
            (
                str(payload.get("endpoint", "")),
                _flatten(payload.get("raw_payload", {})),
            )
        )
    ).lower()

    pattern_confidences = (
        (
            "sql_injection",
            re.compile(
                r"(union\s+(all\s+)?select|select\s+.+\s+from|"
                r"insert\s+into|update\s+.+\s+set|delete\s+from|"
                r"(['\"]\s*(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+))"
            ),
            0.95,
        ),
        (
            "xss",
            re.compile(
                r"(<script\b|javascript\s*:|on(load|error|click)\s*=|"
                r"<img\b[^>]+onerror\s*=)"
            ),
            0.88,
        ),
        (
            "path_traversal",
            re.compile(
                r"(\.\.[\\/]){2,}|%2e%2e|(/etc/passwd|windows[\\/]win\.ini)"
            ),
            0.84,
        ),
        (
            "command_injection",
            re.compile(
                r"(^|[\s;&|])(\$\(|`[^`]+`|"
                r"(id|whoami|uname|cat)\b)"
            ),
            0.86,
        ),
    )

    matched = [
        (name, confidence)
        for name, pattern, confidence in pattern_confidences
        if pattern.search(text)
    ]

    if matched:
        name, confidence = max(matched, key=lambda item: item[1])
        request_rate = float(payload.get("request_rate", 0) or 0)
        failed_logins = int(payload.get("failed_logins", 0) or 0)
        special_characters = int(payload.get("special_characters", 0) or 0)
        behavioral_boost = min(
            0.06,
            (0.02 if request_rate >= 50 else 0)
            + (0.02 if failed_logins >= 10 else 0)
            + (0.02 if special_characters >= 5 else 0),
        )
        return {
            "prediction": "malicious",
            "confidence": round(min(0.99, confidence + behavioral_boost), 2),
        }

    request_rate = float(payload.get("request_rate", 0) or 0)
    failed_logins = int(payload.get("failed_logins", 0) or 0)
    special_characters = int(payload.get("special_characters", 0) or 0)
    anomaly = (
        (0.12 if request_rate >= 100 else 0)
        + (0.12 if failed_logins >= 20 else 0)
        + (0.08 if special_characters >= 10 else 0)
    )
    confidence = round(min(0.39, 0.05 + anomaly), 2)
    return {
        "prediction": "benign" if confidence < 0.25 else "malicious",
        "confidence": confidence,
    }


class MLHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path != "/predict/":
            self.send_response(404)
            self.end_headers()
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length) or b"{}")
            response = classify_telemetry(payload)
        except (ValueError, TypeError, json.JSONDecodeError):
            response = {"prediction": "unknown", "confidence": 0}

        body = json.dumps(response).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

        self.wfile.write(body)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8001), MLHandler)

    print("========================================")
    print("Mock ML Service")
    print("Running: http://127.0.0.1:8001/predict/")
    print("Prediction: deterministic telemetry-based classification")
    print("========================================")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nMock ML service stopped.")
        server.server_close()