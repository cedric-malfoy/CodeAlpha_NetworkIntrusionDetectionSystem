"""Versioned, event-time, five-second bidirectional window features."""
from collections import defaultdict
import hashlib
import math

SCHEMA = "flow5-v1"
WINDOW_SECONDS = 5
FEATURES = (
    "duration_s", "forward_packets", "reverse_packets", "forward_ip_bytes", "reverse_ip_bytes",
    "length_mean", "length_std", "length_min", "length_max", "iat_mean", "iat_std",
    "packets_per_second", "bytes_per_second", "syn_ratio", "rst_ratio", "ack_ratio", "fin_ratio",
    "is_tcp", "is_udp", "is_icmp", "source_connections", "source_destination_ports",
)


def window_key(packet):
    return (int(packet.timestamp // WINDOW_SECONDS), packet.connection)


def window_id(packet):
    return hashlib.sha256(repr(window_key(packet)).encode()).hexdigest()[:24]


class Flow:
    def __init__(self, packet):
        self.src, self.dst, self.sport, self.dport = packet.src, packet.dst, packet.sport, packet.dport
        self.protocol, self.connection = packet.protocol, packet.connection
        self.id = window_id(packet)
        self.bucket = int(packet.timestamp // WINDOW_SECONDS)
        self.first = self.last = packet.timestamp
        self.count = self.forward = self.forward_bytes = self.reverse_bytes = 0
        self.total = self.squares = self.iat_total = self.iat_squares = 0.0
        self.minimum, self.maximum = math.inf, 0
        self.flags = [0, 0, 0, 0]

    def add(self, packet):
        if self.count:
            interval = max(0.0, packet.timestamp - self.last)
            self.iat_total += interval
            self.iat_squares += interval * interval
        self.first, self.last = min(self.first, packet.timestamp), max(self.last, packet.timestamp)
        self.count += 1
        self.total += packet.size
        self.squares += packet.size * packet.size
        self.minimum, self.maximum = min(self.minimum, packet.size), max(self.maximum, packet.size)
        if packet.src == self.src and packet.sport == self.sport:
            self.forward += 1
            self.forward_bytes += packet.size
        else:
            self.reverse_bytes += packet.size
        for index, flag in enumerate((2, 4, 16, 1)):
            self.flags[index] += bool(packet.flags & flag)

    def finish(self, context):
        duration = self.last - self.first
        mean = self.total / self.count
        iat_n = max(1, self.count - 1)
        iat_mean = self.iat_total / iat_n
        values = [duration, self.forward, self.count - self.forward, self.forward_bytes, self.reverse_bytes,
                  mean, math.sqrt(max(0, self.squares / self.count - mean * mean)), self.minimum, self.maximum,
                  iat_mean, math.sqrt(max(0, self.iat_squares / iat_n - iat_mean * iat_mean)),
                  self.count / max(duration, 0.001), self.total / max(duration, 0.001),
                  *(value / self.count for value in self.flags), int(self.protocol == "tcp"),
                  int(self.protocol == "udp"), int(self.protocol == "icmp"),
                  len(context["connections"]), len(context["ports"])]
        assert len(values) == len(FEATURES) and all(math.isfinite(value) for value in values)
        return {"flow_id": self.id, "first": self.first, "last": self.last, "src": self.src,
                "dst": self.dst, "sport": self.sport, "dport": self.dport, "protocol": self.protocol,
                "connection": self.connection, "values": values}


class Extractor:
    def __init__(self, max_flows=10000):
        self.max_flows = max_flows
        self.flows = {}
        self.contexts = defaultdict(lambda: {"connections": set(), "ports": set()})
        self.watermark = -1
        self.dropped = self.late = 0

    def advance(self, timestamp):
        bucket = int(timestamp // WINDOW_SECONDS)
        if bucket <= self.watermark:
            return []
        self.watermark = bucket
        return self._flush(lambda value: value < bucket)

    def push(self, packet):
        emitted = self.advance(packet.timestamp)
        bucket = int(packet.timestamp // WINDOW_SECONDS)
        if bucket < self.watermark:
            self.late += 1
            return emitted
        key = window_key(packet)
        if key not in self.flows:
            if len(self.flows) >= self.max_flows:
                self.dropped += 1
                return emitted
            self.flows[key] = Flow(packet)
        self.flows[key].add(packet)
        context = self.contexts[(bucket, packet.src)]
        context["connections"].add(packet.connection)
        context["ports"].add(packet.dport)
        return emitted

    def _flush(self, predicate):
        emitted = []
        for key in list(self.flows):
            if predicate(key[0]):
                flow = self.flows.pop(key)
                emitted.append(flow.finish(self.contexts[(flow.bucket, flow.src)]))
        for key in list(self.contexts):
            if predicate(key[0]):
                del self.contexts[key]
        return emitted

    def finish(self):
        return self._flush(lambda _bucket: True)
