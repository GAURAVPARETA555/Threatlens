# ThreatLens ML service

Replaces `backend/mock_ml.py` with a trained, calibrated classifier.

```bash
pip install -r ml/requirements.txt
python ml/generate_dataset.py   # run from repo root; PYTHONPATH=ml if import fails
python ml/train.py              # writes ml/threatlens_model.joblib + ml/metrics.json
python ml/serve.py              # http://127.0.0.1:8001/predict/  (same contract as the mock)
```

**Data caveat:** training data is synthetic (no public dataset has these 3 features).
Held-out metrics measure how well the model recovers the generator's rules, not
real-world detection performance. Swap `ml/data/telemetry.csv` for real labelled
logs (columns: request_rate, failed_logins, special_characters, label) and re-run `train.py`.
