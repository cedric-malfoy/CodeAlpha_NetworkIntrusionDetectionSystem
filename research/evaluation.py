"""Explicit operating points and metrics; unknown labels never become benign."""
import numpy as np
from sklearn.metrics import average_precision_score

PRIMARY_MASK = (1 << 1) | (1 << 3)


def safe_divide(a, b):
    return float(a / b) if b else None


def metrics(y, predicted, scores=None):
    y, predicted = np.asarray(y), np.asarray(predicted, dtype=bool)
    known = np.isin(y, [0, 1])
    unknown_alerts = int(np.sum(predicted & ~known))
    y, predicted = y[known], predicted[known]
    positive = y == 1
    tp, fp = int(np.sum(predicted & positive)), int(np.sum(predicted & ~positive))
    fn, tn = int(np.sum(~predicted & positive)), int(np.sum(~predicted & ~positive))
    recall, fpr = safe_divide(tp, tp + fn), safe_divide(fp, fp + tn)
    ap = None
    if scores is not None and len(y) and np.any(positive):
        ap = float(average_precision_score(y, np.asarray(scores)[known]))
    return {"samples": len(y), "benign": tn + fp, "suspicious": tp + fn,
            "precision": safe_divide(tp, tp + fp), "recall": recall,
            "f1": safe_divide(2 * tp, 2 * tp + fp + fn), "false_positive_rate": fpr,
            "balanced_accuracy": (recall + 1 - fpr) / 2 if recall is not None and fpr is not None else None,
            "average_precision": ap, "unknown_windows": int(np.sum(~known)),
            "unknown_alerts": unknown_alerts,
            "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp}}


def select_f1(y, scores):
    if set(np.unique(y)) != {0, 1}:
        raise ValueError("Threshold fitting requires both classes in validation data")
    return float(max(np.linspace(0.05, 0.95, 91),
                     key=lambda t: ((metrics(y, scores >= t)["f1"] or 0), t)))


def budget_threshold(y, scores, budget):
    """Highest recall, then lowest FPR, then highest cutoff. Ties stay together."""
    y, scores = np.asarray(y), np.asarray(scores)
    if set(np.unique(y)) != {0, 1}:
        return {"status": "infeasible", "reason": "validation requires both classes", "threshold": None}
    if not np.isfinite(scores).all() or np.any((scores < 0) | (scores > 1)):
        raise ValueError("Invalid classifier scores")
    order = np.argsort(-scores, kind="stable")
    ordered = scores[order]
    ends = np.r_[np.flatnonzero(ordered[:-1] != ordered[1:]), len(scores) - 1]
    tp = np.r_[0, np.cumsum(y[order] == 1)[ends]]
    fp = np.r_[0, np.cumsum(y[order] == 0)[ends]]
    cutoffs = np.r_[np.nextafter(1.0, 2.0), ordered[ends]]
    recall, fpr = tp / np.sum(y == 1), fp / np.sum(y == 0)
    eligible = np.flatnonzero(fpr <= budget + 1e-12)
    best = max(eligible, key=lambda i: (recall[i], -fpr[i], cutoffs[i]))
    return {"status": "feasible" if recall[best] else "feasible_zero_recall",
            "threshold": float(cutoffs[best]), "validation_recall": float(recall[best]),
            "validation_false_positive_rate": float(fpr[best]), "budget": budget,
            "all_negative": bool(cutoffs[best] > 1)}


def decisions(rule_mask, scores, threshold):
    rules = (np.asarray(rule_mask) & PRIMARY_MASK) != 0
    ml = np.asarray(scores) >= threshold
    return {"rules": rules, "ml": ml, "union": rules | ml}


def incident_index(group):
    keys = np.char.add(np.char.add(group["src"], ">"), group["dst"])
    keys = np.char.add(np.char.add(keys, "@"), (group["first"] // 60).astype(np.int64).astype(str))
    _, indices = np.unique(keys, return_inverse=True)
    state = np.zeros(int(indices.max()) + 1, dtype=np.uint8)
    labels = np.where(group["y"] == 0, 1, np.where(group["y"] == 1, 2, 4)).astype(np.uint8)
    np.bitwise_or.at(state, indices, labels)
    return indices, state


def incident_metrics(group, predicted, index):
    indices, state = index
    flagged = np.bincount(indices, weights=np.asarray(predicted, dtype=int), minlength=len(state)) > 0
    positive = group["y"] == 1
    uids = np.where(group["label_uid"] != "", group["label_uid"], group["connection_id"])
    total_connections = len(np.unique(uids[positive]))
    caught_connections = len(np.unique(uids[positive & predicted]))
    return {"incidents": int(np.sum(flagged)),
            "pure_benign_incidents": int(np.sum(flagged & (state == 1))),
            "mixed_or_unknown_incidents": int(np.sum(flagged & ~np.isin(state, [1, 2]))),
            "malicious_labeled_connections": total_connections,
            "detected_malicious_labeled_connections": caught_connections,
            "malicious_connection_recall": safe_divide(caught_connections, total_connections)}
