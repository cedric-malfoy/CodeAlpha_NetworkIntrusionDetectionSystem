"""Research-only packet extraction retaining negatives, exclusions and rule evidence."""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import time
import urllib.request

import numpy as np

from ids_lab.features import Extractor, FEATURES, window_id, window_key
from ids_lab.labels import LabelIndex
from ids_lab.packets import connection_key, decode, read_pcap
from ids_lab.rules import Rules
from ids_lab.synthetic import lab_sessions
from .common import ROOT, digest, protocol, write_json


class DetailedLabels(LabelIndex):
    """Same join conditions as runtime LabelIndex; append original UID/subtype."""
    def __init__(self, path):
        self.entries, self.skipped = defaultdict(list), 0
        with Path(path).open() as source:
            for line in source:
                if not line.strip() or line.startswith("#"):
                    continue
                row = line.split()
                try:
                    label = {"benign": 0, "malicious": 1}[row[-2].lower()]
                    proto = row[6].lower()
                    if proto not in ("tcp", "udp", "icmp"):
                        raise ValueError("Unsupported protocol")
                    sport, dport = (int(row[3]), int(row[5])) if proto != "icmp" else (0, 0)
                    key = connection_key(proto, row[2], sport, row[4], dport)
                    start = float(row[0])
                    duration = 0.0 if row[8] == "-" else float(row[8])
                    self.entries[key].append((start, start + max(0, duration), label, row[1], row[-1]))
                except (ValueError, KeyError, IndexError):
                    self.skipped += 1
        for entries in self.entries.values():
            entries.sort()

    def describe(self, window):
        label, reason = self.match(window)
        if label is None:
            return -1, reason, "", ""
        candidate = next(entry for entry in self.entries[window["connection"]]
                         if entry[0] - 0.001 <= window["first"] and entry[1] + 1 >= window["last"])
        return label, reason, candidate[3], candidate[4]


def extract(packets, lookup, deadline):
    extractor, rules = Extractor(), Rules()
    pending, rows, stats = {}, defaultdict(list), Counter()
    first, last = None, None

    def consume(windows):
        for w in windows:
            label, reason, uid, subtype = lookup(w)
            stats[reason] += 1
            if label in (0, 1):
                stats["benign" if label == 0 else "suspicious"] += 1
            values = {"X": w["values"], "y": label, "first": w["first"], "last": w["last"],
                      "src": w["src"], "dst": w["dst"], "protocol": w["protocol"],
                      "connection_id": hashlib.sha256(repr(w["connection"]).encode()).hexdigest(),
                      "window_id": w["flow_id"], "label_uid": uid, "subtype": subtype,
                      "label_reason": reason, "rule_mask": pending.pop(w["flow_id"], 0)}
            for key, value in values.items():
                rows[key].append(value)

    for raw in packets:
        stats["packets"] += 1
        if stats["packets"] % 10000 == 0:
            deadline.check()
        packet = decode(raw)
        if packet is None:
            stats["unsupported_or_malformed"] += 1
            continue
        first = packet.timestamp if first is None else min(first, packet.timestamp)
        last = packet.timestamp if last is None else max(last, packet.timestamp)
        consume(extractor.push(packet))
        findings = rules.inspect(packet)
        if findings:
            if window_key(packet) in extractor.flows:
                mask = sum(1 << (int(rule[-3:]) - 1) for rule in findings)
                key = window_id(packet)
                pending[key] = pending.get(key, 0) | mask
            else:
                stats["rule_packets_without_feature_window"] += 1
    consume(extractor.finish())
    stats.update(late_packets=extractor.late, capacity_dropped=extractor.dropped,
                 stream_dropped=rules.stream_drops, orphan_rule_windows=len(pending))
    arrays = {}
    for key, values in rows.items():
        dtype = np.float64 if key in ("X", "first", "last") else np.int8 if key == "y" else np.uint8 if key == "rule_mask" else str
        arrays[key] = np.asarray(values, dtype=dtype)
    if not rows:
        raise ValueError("Capture produced no supported feature windows")
    assert arrays["X"].shape == (len(arrays["y"]), len(FEATURES))
    return arrays, {**stats, "first_timestamp": first, "last_timestamp": last,
                    "capture_span_seconds": (last - first) if first is not None else 0,
                    "duration_warning": "Span includes any capture gaps; it is not verified continuous benign monitoring time."}


def fetch(manifest, output, deadline, fresh=False):
    spec = protocol()
    lock = json.loads((ROOT / "data/sources.lock.json").read_text())["files"] if not fresh else {}
    saved_sources = output / ("fresh_sources.json" if fresh else "sources.json")
    if fresh and saved_sources.exists():
        lock = json.loads(saved_sources.read_text())
    file_records = {}
    total = 0
    for entry in manifest["captures"]:
        for filename in (entry["pcap"], "bro/conn.log.labeled"):
            relative = f"{entry['id']}/{Path(filename).name}"
            url = manifest["base_url"] + entry["directory"] + filename
            target = output / "raw" / relative
            existing = ROOT / "data/raw" / relative
            if not target.exists() and existing.exists() and not fresh:
                target = existing
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                part = target.with_suffix(target.suffix + ".part")
                for attempt in range(3):
                    deadline.check()
                    try:
                        request = urllib.request.Request(url, headers={"User-Agent": "Signalwatch-Research/1"})
                        size = 0
                        with urllib.request.urlopen(request, timeout=60) as response, part.open("wb") as destination:
                            while chunk := response.read(1024 * 1024):
                                deadline.check()
                                size += len(chunk)
                                if size > spec["max_file_bytes"] or total + size > spec["max_download_bytes"]:
                                    raise ValueError("Research download budget exceeded")
                                destination.write(chunk)
                        part.replace(target)
                        break
                    except (OSError, TimeoutError):
                        if attempt == 2:
                            raise
                        time.sleep(1)
            size = target.stat().st_size
            total += size
            if size > spec["max_file_bytes"] or total > spec["max_download_bytes"]:
                raise ValueError("Research download budget exceeded")
            checksum = digest(target)
            if relative in lock and lock[relative]["sha256"] != checksum:
                raise ValueError(f"Source hash mismatch: {relative}")
            file_records[relative] = {"path": str(target.resolve()), "url": url, "sha256": checksum, "bytes": size}
            print(f"Verified {relative}: {size:,} bytes", flush=True)
    write_json(output / ("fresh_sources.json" if fresh else "sources.json"), file_records)
    return file_records


def prepare(output, fingerprint, deadline, smoke=False, fresh=False):
    cache = output / ("fresh_data" if fresh else "data")
    cache.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((ROOT / "data/sources.json").read_text())
    if fresh:
        manifest["captures"] = protocol()["fresh_captures"]
    records = []
    if not smoke:
        files = fetch(manifest, output, deadline, fresh)
        for entry in manifest["captures"]:
            inputs = [files[f"{entry['id']}/{name}"] for name in (entry["pcap"], "conn.log.labeled")]
            identity = hashlib.sha256(json.dumps([fingerprint, [x["sha256"] for x in inputs]]).encode()).hexdigest()
            record_file = cache / f"{entry['id']}.json"
            array_file = record_file.with_suffix(".npz")
            old = json.loads(record_file.read_text()) if record_file.exists() else {}
            if old.get("identity") == identity and array_file.exists() and old.get("array_sha256") == digest(array_file):
                records.append(old)
                print(f"Reused {entry['id']}", flush=True)
                continue
            deadline.check()
            print(f"Extracting {entry['id']}", flush=True)
            labels = DetailedLabels(inputs[1]["path"])
            arrays, stats = extract(read_pcap(inputs[0]["path"]), labels.describe, deadline)
            record = {**entry, "domain": "public", **stats, "identity": identity, "invalid_label_rows": labels.skipped}
            _save_capture(array_file, arrays, record)
            records.append(record)
    if not fresh:
        seen = set()
        for split, group, packets, labels in lab_sessions():
            if smoke and split in seen:
                continue
            seen.add(split)
            deadline.check()
            def lookup(w):
                value = labels.get(w["connection"])
                return (-1 if value is None else value, "unmatched" if value is None else "matched",
                        hashlib.sha256(repr(w["connection"]).encode()).hexdigest(), "generated-intent")
            arrays, stats = extract(packets, lookup, deadline)
            record = {"id": group, "domain": "lab", "split": split, **stats, "identity": fingerprint}
            _save_capture(cache / f"{group}.npz", arrays, record)
            records.append(record)
    write_json(cache / "index.json", {"fingerprint": fingerprint, "smoke": smoke, "captures": records})
    return records


def _save_capture(path, arrays, record):
    temporary = path.with_suffix(".part.npz")
    np.savez_compressed(temporary, **arrays)
    temporary.replace(path)
    record["array_sha256"] = digest(path)
    write_json(path.with_suffix(".json"), record)


def load(output, fresh=False):
    directory = output / ("fresh_data" if fresh else "data")
    index = json.loads((directory / "index.json").read_text())
    groups = {}
    for record in index["captures"]:
        path = directory / f"{record['id']}.npz"
        if digest(path) != record["array_sha256"]:
            raise ValueError(f"Research cache corrupted: {path.name}")
        with np.load(path, allow_pickle=False) as archive:
            groups[record["id"]] = {"record": record, **{key: archive[key] for key in archive.files}}
    return groups
