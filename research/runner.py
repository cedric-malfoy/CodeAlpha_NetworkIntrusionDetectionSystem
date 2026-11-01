"""CPU experiment runner with checkpoints and immutable baseline inputs."""
import argparse
import csv
import json
from pathlib import Path
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from threadpoolctl import threadpool_limits

from .common import ROOT, Deadline, digest, protected_hashes, provenance, protocol, write_json
from .data import load, prepare
from .evaluation import (PRIMARY_MASK, budget_threshold, decisions, incident_index,
                         incident_metrics, metrics, select_f1)


def estimator(name, seed):
    if name == "random_forest":
        return RandomForestClassifier(n_estimators=200, max_depth=10, max_leaf_nodes=256,
                                      class_weight="balanced_subsample", random_state=seed, n_jobs=2)
    if name == "logistic_regression":
        return make_pipeline(StandardScaler(), LogisticRegression(C=1, class_weight="balanced", max_iter=2000,
                                                                  random_state=seed))
    if name == "decision_tree":
        return DecisionTreeClassifier(max_depth=10, min_samples_leaf=5, class_weight="balanced", random_state=seed)
    if name == "hist_gradient_boosting":
        return HistGradientBoostingClassifier(max_iter=200, max_leaf_nodes=31, learning_rate=0.1,
                                               early_stopping=False, class_weight="balanced", random_state=seed)
    raise ValueError(name)


def matrix(groups, split, domain=None):
    selected = [g for g in groups.values() if g["record"]["split"] == split and
                (domain is None or g["record"]["domain"] == domain)]
    if not selected:
        raise ValueError(f"No data for {split}/{domain}")
    return tuple(np.concatenate([g[key][g["y"] >= 0] for g in selected]) for key in ("X", "y"))


def fit_policy(groups, output, name, seed, fingerprint, baseline=False):
    directory = output / "models"
    directory.mkdir(exist_ok=True)
    stem = f"{name}-{seed}" + ("-baseline" if baseline else "")
    path, meta_path = directory / f"{stem}.joblib", directory / f"{stem}.json"
    if meta_path.exists() and path.exists():
        meta = json.loads(meta_path.read_text())
        if meta["fingerprint"] == fingerprint and meta["model_sha256"] == digest(path):
            print(f"Reused model {stem}", flush=True)
            return joblib.load(path), meta
    x, y = matrix(groups, "train")
    model = estimator(name, seed)
    start = time.perf_counter()
    with threadpool_limits(limits=2):
        model.fit(x, y)
    vx, vy = matrix(groups, "validation")
    scores = model.predict_proba(vx)[:, 1]
    cutoff = select_f1(vy, scores)
    policies = {"validation_f1": {"threshold": cutoff, "status": "feasible", "fitted_on": "combined_validation"}}
    if not baseline:
        public = any(g["record"]["domain"] == "public" for g in groups.values())
        bx, by = matrix(groups, "validation", "public" if public else "lab")
        bscores = model.predict_proba(bx)[:, 1]
        for budget in protocol()["false_positive_budgets"]:
            policies[f"fpr_{budget:g}"] = {**budget_threshold(by, bscores, budget),
                                          "fitted_on": "public_validation" if public else "lab_validation_smoke"}
    temporary = path.with_suffix(".part.joblib")
    joblib.dump(model, temporary, compress=3)
    temporary.replace(path)
    meta = {"fingerprint": fingerprint, "model": name, "seed": seed, "model_sha256": digest(path),
            "policies": policies, "fit_seconds": time.perf_counter() - start,
            "training_groups": sorted(k for k, g in groups.items() if g["record"]["split"] == "train"),
            "model_parameters": model.get_params() if name != "logistic_regression" else
                {"scaler": "StandardScaler", "C": 1, "class_weight": "balanced", "max_iter": 2000}}
    write_json(meta_path, meta)
    return model, meta


def evaluate(groups, model, meta, output, label, deadline):
    rows, partitions = [], {}
    pred_dir = output / "predictions" / label
    pred_dir.mkdir(parents=True, exist_ok=True)
    for capture, group in groups.items():
        deadline.check()
        scores = model.predict_proba(group["X"])[:, 1]
        index = incident_index(group)
        frame = pd.DataFrame({key: value for key, value in group.items() if key not in ("X", "record")})
        from ids_lab.features import FEATURES
        for column, values in zip(FEATURES, group["X"].T):
            frame[column] = values
        frame["score"] = scores
        for policy, settings in meta["policies"].items():
            if settings["threshold"] is None:
                continue
            detectors = decisions(group["rule_mask"], scores, settings["threshold"])
            for detector, predicted in detectors.items():
                frame[f"{policy}__{detector}"] = predicted.astype(int)
                key = (group["record"]["split"], group["record"]["domain"], policy, detector)
                result = metrics(group["y"], predicted, scores if detector == "ml" else None)
                incident = incident_metrics(group, predicted, index)
                base = {"model": meta["model"], "seed": meta["seed"], "policy": policy,
                        "detector": detector, "split": key[0], "domain": key[1]}
                rows.append({**base, "level": "capture", "capture": capture, **result, **incident})
                partitions.setdefault(key, []).append((group["y"], predicted, scores, incident))
                for proto in np.unique(group["protocol"]):
                    mask = group["protocol"] == proto
                    rows.append({**base, "level": "protocol", "capture": capture, "protocol": str(proto),
                                 **metrics(group["y"][mask], predicted[mask])})
        frame["raw_event_union"] = ((group["rule_mask"] != 0) | (scores >= meta["policies"]["validation_f1"]["threshold"])).astype(int)
        temporary = pred_dir / f"{capture}.part.csv.gz"
        frame.to_csv(temporary, index=False, compression="gzip")
        temporary.replace(pred_dir / f"{capture}.csv.gz")
    for (split, domain, policy, detector), entries in partitions.items():
        y, predicted, scores = (np.concatenate([entry[i] for entry in entries]) for i in range(3))
        incident = {key: sum(entry[3][key] for entry in entries) for key in entries[0][3] if key != "malicious_connection_recall"}
        n = incident["malicious_labeled_connections"]
        incident["malicious_connection_recall"] = incident["detected_malicious_labeled_connections"] / n if n else None
        rows.append({"model": meta["model"], "seed": meta["seed"], "policy": policy, "detector": detector,
                     "split": split, "domain": domain, "level": "partition", "capture": "ALL",
                     **metrics(y, predicted, scores if detector == "ml" else None), **incident})
    return rows


def baseline(output, groups, fingerprint, deadline, smoke):
    model, meta = fit_policy(groups, output, "random_forest", 42, fingerprint, baseline=True)
    rows = evaluate(groups, model, meta, output, "baseline", deadline)
    checks = []
    if not smoke:
        published = json.loads((ROOT / "reports/model_metrics.json").read_text())
        assert abs(meta["policies"]["validation_f1"]["threshold"] - published["threshold"]) < 1e-12
        for row in rows:
            if row["level"] == "partition" and row["detector"] == "ml":
                expected = published["results"][f"{row['domain']}_{row['split']}"]["random_forest"]
                okay = row["confusion_matrix"] == expected["confusion_matrix"]
                checks.append({"partition": f"{row['domain']}_{row['split']}", "matches": okay})
                if not okay:
                    write_json(output / "baseline_mismatch.json", {"observed": row, "expected": expected})
                    raise ValueError("Baseline confusion matrix differs; inspect baseline_mismatch.json before comparison")
    write_json(output / "baseline.json", {"metadata": meta, "reproduction_checks": checks, "results": rows})
    print("Baseline reproduced" if not smoke else "Synthetic smoke baseline completed", flush=True)


def compare(output, groups, fingerprint, deadline, seeds):
    if not (output / "baseline.json").exists():
        raise ValueError("Run baseline before compare")
    results = []
    for name in ("random_forest", "logistic_regression", "decision_tree", "hist_gradient_boosting"):
        for seed in seeds:
            deadline.check()
            checkpoint = output / "comparisons" / f"{name}-{seed}.json"
            if checkpoint.exists():
                saved = json.loads(checkpoint.read_text())
                predictions_complete = all((output / "predictions" / f"{name}-{seed}" / f"{capture}.csv.gz").exists() for capture in groups)
                if saved["fingerprint"] == fingerprint and predictions_complete:
                    results.extend(saved["results"])
                    continue
            print(f"Comparing {name}, seed {seed}", flush=True)
            model, meta = fit_policy(groups, output, name, seed, fingerprint)
            rows = evaluate(groups, model, meta, output, f"{name}-{seed}", deadline)
            write_json(checkpoint, {"fingerprint": fingerprint, "metadata": meta, "results": rows})
            results.extend(rows)
    write_json(output / "comparisons.json", {"fingerprint": fingerprint, "seeds": seeds, "results": results})
    pd.json_normalize(results).to_csv(output / "metrics.csv", index=False)
    candidate = json.loads((output / "models/random_forest-42.json").read_text())
    reference = json.loads((output / "models/random_forest-42-baseline.json").read_text())
    frozen = {"fingerprint": fingerprint, "candidate_model": "random_forest-42.joblib",
              "candidate_sha256": candidate["model_sha256"], "candidate_policy": "fpr_0.001",
              "candidate_threshold": candidate["policies"]["fpr_0.001"]["threshold"],
              "reference_model": "random_forest-42-baseline.joblib", "reference_sha256": reference["model_sha256"],
              "reference_threshold": reference["policies"]["validation_f1"]["threshold"],
              "selection": "RF seed 42 at 0.1% validation FPR budget was specified before fresh evaluation; not selected by published-test results.",
              "protocol_sha256": digest(ROOT / "research/protocol.json"), "seeds": seeds}
    freeze_path = output / "frozen_policy.json"
    if freeze_path.exists() and json.loads(freeze_path.read_text()) != frozen:
        raise ValueError("Frozen policy already differs. Use a new output directory; do not rewrite an evaluated policy.")
    write_json(freeze_path, frozen)


def evaluate_frozen(output, fingerprint, deadline, smoke):
    if smoke:
        raise ValueError("Fresh public evaluation is not a synthetic smoke stage")
    frozen = json.loads((output / "frozen_policy.json").read_text())
    if frozen["fingerprint"] != fingerprint:
        raise ValueError("Research code changed after policy freeze; use a new experiment")
    if frozen["candidate_threshold"] is None:
        raise ValueError("No feasible candidate threshold")
    result_path = output / "fresh_results.json"
    if result_path.exists():
        if json.loads(result_path.read_text())["frozen_sha256"] != digest(output / "frozen_policy.json"):
            raise ValueError("Fresh results do not match frozen policy")
        print("Reused completed fresh evaluation", flush=True)
        return
    prepare(output, fingerprint, deadline, fresh=True)
    groups = load(output, fresh=True)
    coverage = {}
    for key, group in groups.items():
        coverage[key] = float(np.mean(group["y"] >= 0))
    write_json(output / "fresh_coverage.json", coverage)
    if any(v < protocol()["minimum_fresh_label_coverage"] for v in coverage.values()):
        raise ValueError("Fresh label coverage below 90%; investigate alignment before interpreting detection metrics")
    rows = []
    for kind in ("reference", "candidate"):
        path = output / "models" / frozen[f"{kind}_model"]
        if digest(path) != frozen[f"{kind}_sha256"]:
            raise ValueError("Frozen model hash mismatch")
        model = joblib.load(path)
        meta = {"model": kind, "seed": 42, "policies": {"validation_f1": {
            "threshold": frozen[f"{kind}_threshold"], "status": "feasible"}}}
        rows.extend(evaluate(groups, model, meta, output, f"fresh-{kind}", deadline))
    write_json(result_path, {"frozen_sha256": digest(output / "frozen_policy.json"), "coverage": coverage, "results": rows})


def run(args):
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    current, protected = provenance(), protected_hashes()
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else None
    seeds = [int(x) for x in args.seeds.split(",")] if args.seeds else protocol()["seeds"]
    if 42 not in seeds or len(set(seeds)) != len(seeds):
        raise ValueError("Seeds must be unique and include reference seed 42")
    if manifest and (manifest["fingerprint"] != current["fingerprint"] or manifest["smoke"] != args.smoke or manifest["seeds"] != seeds):
        raise ValueError("Output belongs to a different code/config/environment. Select a new output directory.")
    if manifest is None:
        write_json(manifest_path, {**current, "smoke": args.smoke, "seeds": seeds, "protocol": protocol(),
                                   "protected_files": protected, "status": "created"})
    deadline = Deadline(args.max_seconds)
    stages = ["prepare", "baseline", "compare", "report"] if args.stage == "run" else [args.stage]
    try:
        for stage in stages:
            print(f"Stage: {stage}", flush=True)
            if stage == "prepare":
                prepare(output, current["fingerprint"], deadline, smoke=args.smoke)
            elif stage == "baseline":
                baseline(output, load(output), current["fingerprint"], deadline, args.smoke)
            elif stage == "compare":
                compare(output, load(output), current["fingerprint"], deadline, seeds)
            elif stage == "evaluate-frozen":
                evaluate_frozen(output, current["fingerprint"], deadline, args.smoke)
            elif stage == "report":
                from .report import build_report
                build_report(output)
            write_json(output / f"{stage}.complete.json", {"fingerprint": current["fingerprint"], "status": "completed"})
        if protected_hashes() != protected:
            raise RuntimeError("Published baseline files were modified")
        write_json(output / "last_status.json", {"status": "completed", "stages": stages, "protected_files_unchanged": True})
    except BaseException as error:
        write_json(output / "last_status.json", {"status": "failed", "stage": stage,
                   "error": f"{type(error).__name__}: {error}", "protected_files_unchanged": protected_hashes() == protected})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=["prepare", "baseline", "compare", "evaluate-frozen", "report", "run"])
    parser.add_argument("--output", default=str(ROOT / "artifacts/research/pilot"))
    parser.add_argument("--smoke", action="store_true", help="Synthetic software check only; not research accuracy evidence")
    parser.add_argument("--seeds", help="Comma-separated seeds; default 42–46")
    parser.add_argument("--max-seconds", type=int, default=14400)
    args = parser.parse_args()
    if args.max_seconds <= 0 or args.max_seconds > 14400:
        parser.error("Stage budget must be between 1 and 14400 seconds")
    run(args)


if __name__ == "__main__":
    main()

