"""Deterministic independent lab sessions with scenario-intent labels."""
import random

from scapy.all import DNS, DNSQR, DNSRR, Ether, ICMP, IP, Raw, TCP, UDP

from .packets import decode


def session(seed, timestamp):
    rng = random.Random(seed)
    client, server = f"192.0.2.{rng.randint(2, 240)}", f"198.51.100.{rng.randint(2, 240)}"
    packets, labels = [], {}

    def add(offset, sport, dport, proto, reverse=False, label=0, **kwargs):
        src, dst = (server, client) if reverse else (client, server)
        sp, dp = (dport, sport) if reverse else (sport, dport)
        if proto == "tcp":
            layer = TCP(sport=sp, dport=dp, flags=kwargs.get("flags", "A"), seq=kwargs.get("seq", 100))
        elif proto == "udp":
            layer = UDP(sport=sp, dport=dp)
        else:
            layer = ICMP(type=0 if reverse else 8)
        raw = Ether(src="02:00:00:00:00:20", dst="02:00:00:00:00:10")/IP(src=src, dst=dst)/layer
        if kwargs.get("data") is not None:
            raw /= kwargs["data"] if not isinstance(kwargs["data"], bytes) else Raw(kwargs["data"])
        raw.time = timestamp + offset
        packets.append(raw)
        labels[decode(raw).connection] = label

    # Normal sessions include complete requests, DNS, ping, and occasional loss.
    for index in range(50):
        base = index * rng.uniform(0.7, 1.8)
        sport = 20000 + index * 19 + seed % 13
        if index % 4 == 0:
            add(base, sport, 53, "udp", data=DNS(id=index, qd=DNSQR(qname="normal.lab.example")))
            add(base + rng.uniform(0.01, 0.2), sport, 53, "udp", reverse=True,
                data=DNS(id=index, qr=1, qd=DNSQR(qname="normal.lab.example"), an=DNSRR(rrname="normal.lab.example", rdata=server)))
        elif index % 13 == 0:
            add(base, 0, 0, "icmp")
            add(base + 0.04, 0, 0, "icmp", reverse=True)
        else:
            add(base, sport, 8080, "tcp", flags="S", seq=100)
            if index % 17 == 0:
                continue
            add(base+0.01, sport, 8080, "tcp", reverse=True, flags="SA", seq=200)
            add(base+0.02, sport, 8080, "tcp", flags="A", seq=101)
            add(base+0.03, sport, 8080, "tcp", flags="PA", seq=101, data=b"GET / HTTP/1.1\r\nHost: lab.example\r\n\r\n")
            add(base+0.08, sport, 8080, "tcp", reverse=True, flags="PA", seq=201,
                data=b"HTTP/1.1 200 OK\r\n\r\n"+b"x"*rng.randint(80, 1800))
            add(base+0.12, sport, 8080, "tcp", flags="FA", seq=150)
            add(base+0.14, sport, 8080, "tcp", reverse=True, flags="FA", seq=300)

    # Separate intervals: rapid failed connections and high-rate UDP bursts.
    start = 120.0
    for index in range(rng.randint(35, 70)):
        base = start + index * rng.uniform(0.003, 0.03)
        sport, dport = 40000 + index, 10000 + index * rng.randint(1, 5)
        add(base, sport, dport, "tcp", label=1, flags="S")
        add(base+0.001, sport, dport, "tcp", reverse=True, label=1, flags="RA")
    for index in range(12):
        base = 140 + index * 5
        for packet in range(rng.randint(20, 60)):
            add(base + packet * rng.uniform(0.001, 0.006), 50000+index, 9999, "udp", label=1,
                data=b"LAB-BURST"*rng.randint(4, 30))
    packets.sort(key=lambda packet: float(packet.time))
    return packets, labels


def lab_sessions():
    for split, count, seed_start in (("train", 12, 100), ("validation", 5, 300), ("test", 6, 600)):
        for index in range(count):
            seed = seed_start + index
            packets, labels = session(seed, 1700000000 + seed * 1000)
            yield split, f"lab-{seed}", packets, labels
