"""Join official connection labels; do not label an entire infected capture malicious."""
from collections import defaultdict

from .packets import connection_key


class LabelIndex:
    def __init__(self, path):
        self.entries = defaultdict(list)
        self.skipped = 0
        with open(path) as source:
            for line in source:
                if not line.strip() or line.startswith("#"):
                    continue
                row = line.split()
                try:
                    label = {"benign": 0, "malicious": 1}[row[-2].lower()]
                    proto = row[6].lower()
                    if proto not in ("tcp", "udp", "icmp"):
                        raise ValueError("Unsupported protocol")
                    sport = int(row[3]) if proto != "icmp" else 0
                    dport = int(row[5]) if proto != "icmp" else 0
                    key = connection_key(proto, row[2], sport, row[4], dport)
                    start = float(row[0])
                    duration = 0.0 if row[8] == "-" else float(row[8])
                    self.entries[key].append((start, start + max(0.0, duration), label))
                except (ValueError, KeyError, IndexError):
                    self.skipped += 1
        for values in self.entries.values():
            values.sort()

    def match(self, window):
        # First/last packet must fit exactly one official connection interval.
        # One second end tolerance accommodates final TCP teardown packets.
        candidates = [entry for entry in self.entries.get(window["connection"], ())
                      if entry[0] - 0.001 <= window["first"] and entry[1] + 1.0 >= window["last"]]
        if len(candidates) == 1:
            return candidates[0][2], "matched"
        return None, "ambiguous" if candidates else "unmatched"
