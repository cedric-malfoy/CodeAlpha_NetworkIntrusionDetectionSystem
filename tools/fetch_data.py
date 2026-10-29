"""Fetch the frozen public subset; never transmit benchmark packets or fetch binaries."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    source = json.loads((ROOT / "data/sources.json").read_text())
    lock_path = ROOT / "data/sources.lock.json"
    old = json.loads(lock_path.read_text()).get("files", {}) if lock_path.exists() else {}
    jobs = []
    for capture in source["captures"]:
        for kind, filename in (("pcap", capture["pcap"]), ("labels", "bro/conn.log.labeled")):
            relative = f"{capture['id']}/{Path(filename).name}"
            jobs.append((relative, source["base_url"] + capture["directory"] + filename))

    def fetch(item):
        relative, url = item
        destination = ROOT / "data/raw" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            temporary = destination.with_suffix(destination.suffix + ".part")
            request = urllib.request.Request(url, headers={"User-Agent": "CodeAlpha-Custom-IDS-Research/1.0"})
            total = 0
            with urllib.request.urlopen(request, timeout=60) as response, temporary.open("wb") as output:
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > 128 * 1024 * 1024:
                        raise RuntimeError("A file exceeds this subset's 128 MiB limit.")
                    output.write(chunk)
            temporary.replace(destination)
        digest = hashlib.file_digest(destination.open("rb"), "sha256").hexdigest()
        if relative in old and old[relative]["sha256"] != digest:
            raise RuntimeError(f"Dataset hash mismatch: {relative}")
        print(f"Verified {relative}: {destination.stat().st_size:,} bytes", flush=True)
        return relative, {"url": url, "sha256": digest, "bytes": destination.stat().st_size}

    with ThreadPoolExecutor(max_workers=4) as pool:
        files = dict(pool.map(fetch, jobs))
    if sum(item["bytes"] for item in files.values()) > 256 * 1024 * 1024:
        raise RuntimeError("Subset exceeds 256 MiB total download budget.")
    lock_path.write_text(json.dumps({"dataset": source["dataset"], "license": source["license"], "files": files}, indent=2) + "\n")
    print("Public capture/label hashes locked; no dataset files added to Git.")


if __name__ == "__main__":
    main()
