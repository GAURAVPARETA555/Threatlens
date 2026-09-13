from http.server import BaseHTTPRequestHandler, HTTPServer
import json


class MLHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path != "/predict/":
            self.send_response(404)
            self.end_headers()
            return

        response = {
            "prediction": "malicious",
            "confidence": 0.95
        }

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
    print("Prediction: malicious")
    print("Confidence: 0.95")
    print("========================================")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nMock ML service stopped.")
        server.server_close()