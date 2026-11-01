"""Provenance, atomic checkpoints, and bounded stages."""
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")
    temporary.replace(path)


def protocol():
    return json.loads((ROOT / "research/protocol.json").read_text())


def provenance():
    paths = sorted(set(ROOT.glob("research/*.py")) | set(ROOT.glob("ids_lab/*.py")) |
                   {ROOT / "research/protocol.json", ROOT / "requirements-research.txt",
                    ROOT / "data/sources.json", ROOT / "data/sources.lock.json"})
    hashes = {str(p.relative_to(ROOT)): digest(p) for p in paths}
    versions = {name: importlib.metadata.version(name) for name in
                ("numpy", "scipy", "scikit-learn", "scapy", "joblib", "matplotlib", "pandas")}
    fingerprint = hashlib.sha256(json.dumps([hashes, versions], sort_keys=True).encode()).hexdigest()
    if (ROOT / "RESEARCH_SOURCE.json").exists():
        source = json.loads((ROOT / "RESEARCH_SOURCE.json").read_text())
        commit, dirty = source["commit"], source["dirty"]
    else:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True))
    return {"created_at": datetime.now(timezone.utc).isoformat(), "commit": commit, "dirty": dirty,
            "source_sha256": hashes, "versions": versions, "fingerprint": fingerprint}


class Deadline:
    def __init__(self, seconds=14400):
        self.end = time.monotonic() + seconds

    def check(self):
        if time.monotonic() >= self.end:
            raise TimeoutError("Stage time budget exceeded. Completed capture/model checkpoints can be reused.")


def protected_hashes():
    return {str(p.relative_to(ROOT)): digest(p) for pattern in
            ("models/*", "reports/*.json", "data/sources*.json") for p in ROOT.glob(pattern) if p.is_file()}

