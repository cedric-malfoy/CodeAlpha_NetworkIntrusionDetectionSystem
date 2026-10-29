"""Extract the exact runtime features from frozen public captures and lab sessions."""
from collections import Counter
import json
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ids_lab.features import Extractor, FEATURES, SCHEMA
from ids_lab.labels import LabelIndex
from ids_lab.packets import decode, read_pcap
from ids_lab.synthetic import lab_sessions


def extract(raw_packets, label_lookup):
    extractor = Extractor()
    rows, labels, statistics = [], [], Counter()
    def consume(windows):
        for window in windows:
            label, reason = label_lookup(window)
            statistics[reason] += 1
            if label is not None:
                rows.append(window["values"])
                labels.append(label)
    for raw in raw_packets:
        statistics["packets"] += 1
        packet = decode(raw)
        if packet is None:
            statistics["unsupported_or_malformed"] += 1
            continue
        consume(extractor.push(packet))
    consume(extractor.finish())
    statistics["late_packets"] = extractor.late
    statistics["capacity_dropped"] = extractor.dropped
    statistics["benign"] = labels.count(0)
    statistics["suspicious"] = labels.count(1)
    return rows, labels, dict(statistics)


def main():
    output = ROOT / "data/processed"
    output.mkdir(parents=True, exist_ok=True)
    source = json.loads((ROOT / "data/sources.json").read_text())
    stats = {"schema": SCHEMA, "features": list(FEATURES), "captures": []}
    for capture in source["captures"]:
        target = output / f"{capture['id']}.npz"
        if target.exists():
            record = json.loads(target.with_suffix(".json").read_text())
            stats["captures"].append(record)
            print(f"Using cached {capture['id']}", flush=True)
            continue
        print(f"Extracting {capture['id']} ({capture['split']})...", flush=True)
        directory = ROOT / "data/raw" / capture["id"]
        index = LabelIndex(directory / "conn.log.labeled")
        rows, labels, counts = extract(read_pcap(directory / capture["pcap"]), index.match)
        np.savez_compressed(target, X=np.asarray(rows, dtype=np.float64), y=np.asarray(labels, dtype=np.int8))
        record = {"id": capture["id"], "split": capture["split"], "domain": "public", "invalid_label_rows": index.skipped, **counts}
        target.with_suffix(".json").write_text(json.dumps(record, indent=2))
        stats["captures"].append(record)
        print(json.dumps(record), flush=True)
    for split, group, packets, labels in lab_sessions():
        rows, values, counts = extract(packets, lambda window: (labels.get(window["connection"]), "matched"))
        np.savez_compressed(output / f"{group}.npz", X=np.asarray(rows, dtype=np.float64), y=np.asarray(values, dtype=np.int8))
        stats["captures"].append({"id": group, "split": split, "domain": "lab", **counts})
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports/data_quality.json").write_text(json.dumps(stats, indent=2) + "\n")
    print("Prepared public and independent lab partitions.", flush=True)


if __name__ == "__main__":
    main()
