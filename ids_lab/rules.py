"""Our bounded rule engine: no expressions, external IDS, or dynamic code execution."""
from collections import OrderedDict, deque
import json
from pathlib import Path
import re
from urllib.parse import unquote


def load_rules(path=None):
    path = Path(path) if path else Path(__file__).resolve().parents[1] / "config/rules.json"
    config = json.loads(path.read_text())
    if not 1 <= config["syn_count"] <= 10000 or not 0 < config["syn_seconds"] <= 300:
        raise ValueError("Invalid SYN threshold")
    return config


class Stream:
    """First-seen TCP bytes, bounded reordering, and a maximum of 64 KiB per stream."""
    def __init__(self, sequence, timestamp):
        self.next = sequence
        self.data = bytearray()
        self.pending = {}
        self.last = timestamp

    def append(self, sequence, payload, timestamp):
        self.last = timestamp
        if len(self.data) + sum(map(len, self.pending.values())) + len(payload) > 65536:
            return False
        if sequence > self.next:
            if len(self.pending) >= 16:
                return False
            self.pending.setdefault(sequence, payload)
            return True
        overlap = self.next - sequence
        if overlap < len(payload):
            self.data.extend(payload[overlap:])
            self.next += len(payload) - overlap
        for start in sorted(list(self.pending)):
            if start > self.next:
                break
            value = self.pending.pop(start)
            overlap = self.next - start
            if overlap < len(value):
                self.data.extend(value[overlap:])
                self.next += len(value) - overlap
        return True


class Rules:
    def __init__(self, config=None):
        self.config = config or load_rules()
        self.syns = OrderedDict()
        self.streams = OrderedDict()
        self.stream_drops = 0

    def inspect(self, packet):
        found = []
        if packet.echo_request:
            found.append("CUSTOM-001")
        if packet.protocol == "tcp" and packet.flags & 2 and not packet.flags & 16:
            key = (packet.src, packet.dst)
            pending = self.syns.setdefault(key, deque(maxlen=10001))
            while pending and pending[0] < packet.timestamp - self.config["syn_seconds"]:
                pending.popleft()
            pending.append(packet.timestamp)
            self.syns.move_to_end(key)
            if len(pending) > self.config["syn_count"]:
                found.append("CUSTOM-002")
            if len(self.syns) > 4096:
                self.syns.popitem(last=False)
        if packet.dns_name == self.config["dns_indicator"].lower():
            found.append("CUSTOM-005")
        if packet.protocol == "tcp" and packet.dport in self.config["http_ports"]:
            found.extend(self._http(packet))
        return found

    def _http(self, packet):
        key = (packet.src, packet.sport, packet.dst, packet.dport)
        for old_key in list(self.streams):
            if packet.timestamp - self.streams[old_key].last > 30:
                del self.streams[old_key]
        if packet.flags & 2:
            self.streams[key] = Stream(packet.seq + 1, packet.timestamp)
        if not packet.payload:
            return []
        stream = self.streams.setdefault(key, Stream(packet.seq, packet.timestamp))
        self.streams.move_to_end(key)
        if len(self.streams) > 128:
            self.streams.popitem(last=False)
            self.stream_drops += 1
        if not stream.append(packet.seq, packet.payload, packet.timestamp):
            self.streams.pop(key, None)
            self.stream_drops += 1
            return []
        result = []
        while b"\r\n\r\n" in stream.data:
            header_end = stream.data.index(b"\r\n\r\n") + 4
            header = bytes(stream.data[:header_end])
            first = header.split(b"\r\n", 1)[0].split()
            if len(first) != 3 or not first[2].startswith(b"HTTP/"):
                break
            length_match = re.search(rb"(?im)^content-length:\s*(\d+)\s*$", header)
            length = int(length_match.group(1)) if length_match else 0
            if length > 65536:
                self.stream_drops += 1
                self.streams.pop(key, None)
                break
            if len(stream.data) < header_end + length:
                break
            path = first[1].decode("ascii", "replace")
            for _ in range(2):
                path = unquote(path)
            if ".." in path.replace("\\", "/").split("/"):
                result.append("CUSTOM-004")
            body = bytes(stream.data[header_end:header_end + length])
            if first[0] == b"POST" and b"application/x-www-form-urlencoded" in header.lower() and re.search(rb"(?:^|&)password=", body, re.I):
                result.append("CUSTOM-003")
            del stream.data[:header_end + length]
        return list(dict.fromkeys(result))
