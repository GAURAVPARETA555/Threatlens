"""Train, compare and persist the ThreatLens classifier."""
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, classification_report,
                             confusion_matrix, roc_auc_score)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from generate_dataset import FEATURES

df = pd.read_csv("ml/data/telemetry.csv")
X, y = df[FEATURES], df["label"]
X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

candidates = {
    "logreg_baseline": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000)),
    "random_forest": RandomForestClassifier(n_estimators=200, min_samples_leaf=5, random_state=42, n_jobs=-1),
    "hist_gradient_boosting": HistGradientBoostingClassifier(max_depth=4, learning_rate=0.08, random_state=42),
}

cv = StratifiedKFold(5, shuffle=True, random_state=42)
scores = {}
for name, model in candidates.items():
    s = cross_val_score(model, X_tr, y_tr, cv=cv, scoring="average_precision", n_jobs=-1)
    scores[name] = (s.mean(), s.std())
    print(f"{name:24s} CV PR-AUC = {s.mean():.4f} ± {s.std():.4f}")

best = max(scores, key=lambda k: scores[k][0])
print("selected:", best)

# calibrate so `confidence` is a trustworthy probability (feeds the 50% ML term of the risk score)
model = CalibratedClassifierCV(candidates[best], method="isotonic", cv=5)
model.fit(X_tr, y_tr)

proba = model.predict_proba(X_te)[:, 1]
pred = (proba >= 0.5).astype(int)
metrics = {
    "selected_model": best,
    "cv_pr_auc": {k: round(v[0], 4) for k, v in scores.items()},
    "test_roc_auc": round(roc_auc_score(y_te, proba), 4),
    "test_pr_auc": round(average_precision_score(y_te, proba), 4),
    "confusion_matrix [[TN,FP],[FN,TP]]": confusion_matrix(y_te, pred).tolist(),
    "report": classification_report(y_te, pred, output_dict=True, digits=4),
    "n_train": int(len(X_tr)), "n_test": int(len(X_te)),
    "data_source": "synthetic (ml/generate_dataset.py)",
}
print(classification_report(y_te, pred, digits=4))
print("ROC-AUC", metrics["test_roc_auc"], "| PR-AUC", metrics["test_pr_auc"])
print(confusion_matrix(y_te, pred))

joblib.dump({"model": model, "features": FEATURES}, "ml/threatlens_model.joblib", compress=3)
json.dump(metrics, open("ml/metrics.json", "w"), indent=2)
