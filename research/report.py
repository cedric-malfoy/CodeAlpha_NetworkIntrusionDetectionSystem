"""Readable findings and standalone figures from completed measurements."""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from .common import write_json


def pct(value):
    return "undefined" if value is None else f"{100 * value:.2f}%"


def build_report(output):
    baseline = json.loads((output / "baseline.json").read_text())
    comparison = json.loads((output / "comparisons.json").read_text()) if (output / "comparisons.json").exists() else None
    manifest = json.loads((output / "manifest.json").read_text())
    rows = baseline["results"]
    figures = output / "figures"
    figures.mkdir(exist_ok=True)
    focus = [r for r in rows if r["level"] == "partition" and r["split"] == "test" and r["detector"] == "ml"]
    lines = ["# Signalwatch false-alarm study", "",
             "SYNTHETIC SOFTWARE SMOKE RUN — not research accuracy evidence." if manifest["smoke"] else
             "Published-test results are diagnostic/exploratory. Fresh evaluation uses a separately frozen policy.",
             "", f"Source commit: `{manifest['commit']}`. Code fingerprint: `{manifest['fingerprint']}`.",
             "", "## Baseline", "", "| Domain | Windows | Precision | Recall | F1 | False-positive rate |",
             "|---|---:|---:|---:|---:|---:|"]
    for r in focus:
        lines.append(f"| {r['domain']} | {r['samples']:,} | {pct(r['precision'])} | {pct(r['recall'])} | {pct(r['f1'])} | {pct(r['false_positive_rate'])} |")
    lines += ["", "Reproduction checks: " + ("all recorded confusion matrices match." if baseline["reproduction_checks"] and
               all(r["matches"] for r in baseline["reproduction_checks"]) else "synthetic smoke run; published metrics were not checked."),
              "", "## Where baseline mistakes occur", "",
              "| Capture | Benign windows | False positives | FPR | Suspicious windows | Recall |",
              "|---|---:|---:|---:|---:|---:|"]
    captures = [r for r in rows if r["level"] == "capture" and r["split"] == "test" and r["detector"] == "ml"]
    for r in captures:
        lines.append(f"| {r['capture']} | {r['benign']:,} | {r['confusion_matrix']['fp']:,} | {pct(r['false_positive_rate'])} | {r['suspicious']:,} | {pct(r['recall'])} |")
    pub = [r for r in captures if r["domain"] == "public"]
    if pub:
        fig, ax = plt.subplots(figsize=(7, 4))
        ax.bar([r["capture"] for r in pub], [100 * (r["false_positive_rate"] or 0) for r in pub])
        ax.set(ylabel="False-positive rate (%)", title="Published-test baseline by capture")
        ax.tick_params(axis="x", rotation=15)
        fig.tight_layout()
        for ext in ("pdf", "png"):
            fig.savefig(figures / f"baseline_fpr.{ext}", dpi=200)
        plt.close(fig)
    diagnostics = []
    from ids_lab.features import FEATURES
    for r in captures:
        frame = pd.read_csv(output / "predictions/baseline" / f"{r['capture']}.csv.gz", keep_default_na=False)
        benign = frame[frame.y == 0]
        fp = benign[benign.validation_f1__ml == 1]
        tn = benign[benign.validation_f1__ml == 0]
        for feature in FEATURES:
            diagnostics.append({"capture": r["capture"], "feature": feature, "false_positives": len(fp),
                                "true_negatives": len(tn), "fp_median": float(fp[feature].median()) if len(fp) else None,
                                "tn_median": float(tn[feature].median()) if len(tn) else None})
    pd.DataFrame(diagnostics).to_csv(output / "feature_diagnostics.csv", index=False)
    lines += ["", "Feature medians for mistaken and correctly rejected benign traffic are in `feature_diagnostics.csv`. "
              "Differences describe associations; they do not establish a causal explanation."]
    if comparison:
        selected = [r for r in comparison["results"] if r["level"] == "partition" and r["split"] == "test"
                    and r["seed"] == 42 and r["detector"] == "ml"]
        lines += ["", "## Classifier comparisons (seed 42)", "",
                  "| Domain | Model | Validation policy | Recall | FPR | F1 |",
                  "|---|---|---|---:|---:|---:|"]
        for r in selected:
            lines.append(f"| {r['domain']} | {r['model']} | {r['policy']} | {pct(r['recall'])} | {pct(r['false_positive_rate'])} | {pct(r['f1'])} |")
        public = [r for r in selected if r["domain"] == "public" and r["recall"] is not None and r["false_positive_rate"] is not None]
        if public:
            fig, ax = plt.subplots(figsize=(7, 5))
            for name in dict.fromkeys(r["model"] for r in public):
                points = [r for r in public if r["model"] == name]
                ax.scatter([100*r["false_positive_rate"] for r in points], [100*r["recall"] for r in points], label=name)
            ax.set(xlabel="Test false-positive rate (%)", ylabel="Test recall (%)", title="Validation-selected operating points on published test")
            ax.legend(fontsize=8)
            fig.tight_layout()
            for ext in ("pdf", "png"):
                fig.savefig(figures / f"operating_points.{ext}", dpi=200)
            plt.close(fig)
        table = [r"\begin{tabular}{llrrr}", r"Model & Policy & Recall & FPR & F1 \\", r"\hline"]
        for r in public:
            escape = lambda s: s.replace("_", r"\_")
            table.append(f"{escape(r['model'])} & {escape(r['policy'])} & {pct(r['recall']).replace('%', r'\%')} & {pct(r['false_positive_rate']).replace('%', r'\%')} & {pct(r['f1']).replace('%', r'\%')} " + r"\\")
        table.append(r"\end{tabular}")
        (output / "results_table.tex").write_text("\n".join(table) + "\n")
    fresh = json.loads((output / "fresh_results.json").read_text()) if (output / "fresh_results.json").exists() else None
    decision = {"paper_ready": False, "reason": "Fresh evidence and a differentiated contribution are required."}
    if fresh:
        main = {r["model"]: r for r in fresh["results"] if r["level"] == "partition" and r["detector"] == "ml"}
        ref, candidate = main["reference"], main["candidate"]
        reduction = (1 - candidate["false_positive_rate"] / ref["false_positive_rate"]) if ref["false_positive_rate"] else None
        loss = ref["recall"] - candidate["recall"] if ref["recall"] is not None and candidate["recall"] is not None else None
        decision.update(false_positive_reduction=reduction, recall_loss=loss,
                        pilot_target_met=bool(reduction is not None and reduction >= 0.2 and loss is not None and loss <= 0.02))
        lines += ["", "## Fresh-capture check", "",
                  f"Reference FPR {pct(ref['false_positive_rate'])}; candidate FPR {pct(candidate['false_positive_rate'])}.",
                  f"Reference recall {pct(ref['recall'])}; candidate recall {pct(candidate['recall'])}.",
                  f"Pilot improvement target met: {decision['pilot_target_met']}. This is not a publication decision."]
    else:
        lines += ["", "## Fresh-capture check", "", "Pending. No fresh-data improvement is claimed."]
    lines += ["", "## Interpretation and next decision", "",
              "- RF, rules, and their union are evaluated on the same supported windows. Only CUSTOM-002 and CUSTOM-004 enter primary intrusion metrics.",
              "- Other rule findings and the application's full event union are preserved in prediction exports. They have different meanings from malicious-flow labels.",
              "- Incident grouping can change item counts. Pure-benign incident counts require every observed window in that group to be labeled benign; mixed/unknown groups are reported separately.",
              "- Connection recall uses published connection labels. It is not independently annotated attack-episode recall.",
              "- Capture spans can include gaps. False incidents per benign monitoring hour and end-to-end latency are not established by these offline measurements.",
              "- Seeds measure model variability; they do not create independent network environments. Few test captures do not support narrow confidence intervals or broad generalization claims.",
              "- The pilot target is 20% fewer false positives with at most a two-percentage-point recall loss on fresh captures; it is a project criterion, not an IEEE requirement.",
              "- A full paper additionally requires a distinct contribution, more independent evaluation data, appropriate comparisons, and a full-text related-work review.", ""]
    (output / "FINDINGS.md").write_text("\n".join(lines))
    write_json(output / "research_decision.json", decision)
    print(f"Findings: {output / 'FINDINGS.md'}", flush=True)
