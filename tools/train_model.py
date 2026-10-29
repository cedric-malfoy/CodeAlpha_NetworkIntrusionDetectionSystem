"""Train on train only, choose a validation threshold, then evaluate frozen tests."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import sys
import time

import joblib
import numpy as np
import sklearn
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, precision_score, recall_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ids_lab.features import FEATURES, SCHEMA


def metrics(y, scores, threshold):
    predictions = scores >= threshold
    tn, fp, fn, tp = confusion_matrix(y, predictions, labels=[0, 1]).ravel()
    return {"samples": len(y), "benign": int(sum(y == 0)), "suspicious": int(sum(y == 1)),
            "precision": float(precision_score(y, predictions, zero_division=0)),
            "recall": float(recall_score(y, predictions, zero_division=0)),
            "f1": float(f1_score(y, predictions, zero_division=0)),
            "pr_auc_average_precision": float(average_precision_score(y, scores)),
            "false_positive_rate": float(fp / max(1, fp + tn)),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}


def main():
    quality = json.loads((ROOT / "reports/data_quality.json").read_text())
    partitions = {}
    groups = {name: set() for name in ("train", "validation", "test")}
    for record in quality["captures"]:
        groups[record["split"]].add(record["id"])
        data = np.load(ROOT / "data/processed" / f"{record['id']}.npz", allow_pickle=False)
        key = (record["split"], record["domain"])
        partitions.setdefault(key, [[], []])
        partitions[key][0].append(data["X"])
        partitions[key][1].append(data["y"])
    assert not (groups["train"] & groups["test"] or groups["validation"] & groups["test"] or groups["train"] & groups["validation"])
    partitions = {key: (np.concatenate(parts[0]), np.concatenate(parts[1])) for key, parts in partitions.items()}
    def combined(split):
        return tuple(np.concatenate([part[index] for (name, _), part in partitions.items() if name == split]) for index in (0, 1))
    train_x, train_y = combined("train")
    assert len(train_x) <= 150000, "Explicitly review a larger training subset before using it."
    model = RandomForestClassifier(n_estimators=200, max_depth=10, max_leaf_nodes=256,
                                   class_weight="balanced_subsample", random_state=42, n_jobs=2)
    model.fit(train_x, train_y)
    validation_x, validation_y = combined("validation")
    validation_scores = model.predict_proba(validation_x)[:, 1]
    candidates = np.linspace(0.05, 0.95, 91)
    # Deterministic tie break: highest threshold among those with best F1.
    threshold = max(candidates, key=lambda value: (f1_score(validation_y, validation_scores >= value, zero_division=0), value))
    baseline = DummyClassifier(strategy="most_frequent").fit(train_x, train_y)
    results = {}
    for (split, domain), (x, y) in partitions.items():
        scores = model.predict_proba(x)[:, 1]
        results[f"{domain}_{split}"] = {"random_forest": metrics(y, scores, threshold),
                                      "majority_baseline": metrics(y, baseline.predict_proba(x)[:, 1], 0.5)}
    latency = []
    for row in train_x[:100]:
        start = time.perf_counter()
        model.predict_proba(row.reshape(1, -1))
        latency.append((time.perf_counter() - start) * 1000)
    output = ROOT / "models"
    output.mkdir(exist_ok=True)
    joblib.dump(model, output / "detector.joblib", compress=3)
    metadata = {
        "model_version": "custom-rf-v1", "created_at": datetime.now(timezone.utc).isoformat(),
        "schema": SCHEMA, "features": list(FEATURES), "threshold": float(threshold),
        "sha256": hashlib.sha256((output / "detector.joblib").read_bytes()).hexdigest(),
        "sklearn_version": sklearn.__version__, "python": platform.python_version(),
        "hyperparameters": model.get_params(), "partitions": {name: sorted(values) for name, values in groups.items()},
        "dataset_lock_sha256": hashlib.sha256((ROOT / "data/sources.lock.json").read_bytes()).hexdigest(),
        "inference_single_window_ms": {"median": float(np.median(latency)), "p95": float(np.percentile(latency, 95))},
        "score_meaning": "Uncalibrated Random Forest suspicious-class score, not probability of an attack.",
        "feature_importances": dict(zip(FEATURES, model.feature_importances_.tolist())),
    }
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (ROOT / "reports/model_metrics.json").write_text(json.dumps({"threshold": float(threshold), "results": results, "latency": metadata["inference_single_window_ms"]}, indent=2) + "\n")
    print(json.dumps({"threshold": float(threshold), "public_test": results["public_test"], "lab_test": results["lab_test"], "model_bytes": (output / "detector.joblib").stat().st_size}, indent=2))


if __name__ == "__main__":
    main()
