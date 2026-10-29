"""A single packet representation for offline and live processing."""
from dataclasses import dataclass
import ipaddress
import math

from scapy.all import DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP, PcapReader
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6ExtHdrFragment


@dataclass(frozen=True)
class Packet:
    timestamp: float
    src: str
    dst: str
    sport: int
    dport: int
    protocol: str
    size: int
    flags: int = 0
    seq: int = 0
    payload: bytes = b""
    dns_name: str = ""
    echo_request: bool = False

    @property
    def connection(self):
        return (self.protocol, *sorted(((self.src, self.sport), (self.dst, self.dport))))


def connection_key(protocol, src, sport, dst, dport):
    return (protocol, *sorted(((str(ipaddress.ip_address(src)), int(sport)), (str(ipaddress.ip_address(dst)), int(dport)))))


def decode(raw):
    """Reject fragments and malformed/unsupported packets rather than invent fields."""
    try:
        timestamp = float(raw.time)
        if not math.isfinite(timestamp) or timestamp < 0:
            return None
        if IP in raw:
            network = raw[IP]
            if network.frag or int(network.flags) & 1:
                return None
            size = int(network.len or len(bytes(network)))
        elif IPv6 in raw:
            if IPv6ExtHdrFragment in raw:
                return None
            network = raw[IPv6]
            size = 40 + int(network.plen if network.plen is not None else len(bytes(network.payload)))
        else:
            return None
        src, dst = str(ipaddress.ip_address(network.src)), str(ipaddress.ip_address(network.dst))
        if TCP in network:
            layer = network[TCP]
            return Packet(timestamp, src, dst, int(layer.sport), int(layer.dport), "tcp", size,
                          int(layer.flags), int(layer.seq), bytes(layer.payload)[:65536])
        if UDP in network:
            layer = network[UDP]
            name = ""
            if DNS in layer and layer[DNS].qr == 0 and layer[DNS].qd:
                question = layer[DNS].qd
                if isinstance(question, list):
                    question = question[0]
                name = question.qname.decode("ascii", "replace").rstrip(".").lower()[:253]
            return Packet(timestamp, src, dst, int(layer.sport), int(layer.dport), "udp", size,
                          payload=bytes(layer.payload)[:65536], dns_name=name)
        if ICMP in network or ICMPv6EchoRequest in network:
            echo = ICMPv6EchoRequest in network or int(network[ICMP].type) == 8
            return Packet(timestamp, src, dst, 0, 0, "icmp", size, echo_request=echo)
    except (ValueError, TypeError, AttributeError, IndexError, OverflowError):
        return None
    return None


def read_pcap(path):
    # Scapy/PcapReader understands gzip, while xz is supplied as a file object.
    import lzma
    source = lzma.open(path, "rb") if str(path).endswith(".xz") else str(path)
    try:
        with PcapReader(source) as reader:
            yield from reader
    finally:
        if not isinstance(source, str):
            source.close()
