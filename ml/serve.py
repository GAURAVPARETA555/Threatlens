"""Drop-in replacement for backend/mock_ml.py that serves the trained model.

Same contract: POST /predict/ {request_rate, failed_logins, special_characters}
              -> {"prediction": "malicious"|"benign", "confidence": float}
`confidence` is the probability of the *predicted* class, which is what
risk_engine.calculate_risk() expects.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

import joblib
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE = joblib.load(os.path.join(HERE, "threatlens_model.joblib"))
MODEL, FEATURES = BUNDLE["model"], BUNDLE["features"]


def predict(payload: dict) -> dict:
    row = {f: max(0.0, float(payload.get(f, 0))) for f in FEATURES}
    p_mal = float(MODEL.predict_proba(pd.DataFrame([row], columns=FEATURES))[0, 1])
    label = "malicious" if p_mal >= 0.5 else "benign"
    return {"prediction": label,
            "confidence": round(p_mal if label == "malicious" else 1 - p_mal, 4)}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/predict/":
            self.send_response(404); self.end_headers(); return
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.dumps(predict(json.loads(self.rfile.read(n) or b"{}"))).encode()
            code = 200
        except (ValueError, TypeError):
            body, code = b'{"error":"invalid payload"}', 400
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        return


if __name__ == "__main__":
    print("ThreatLens ML service on http://127.0.0.1:8001/predict/")
    HTTPServer(("127.0.0.1", 8001), Handler).serve_forever()
