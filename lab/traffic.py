"""Generate bounded scenarios against the named mock target in our Docker lab."""
import argparse
import http.client
import json
import socket
import time

from scapy.all import DNS, DNSQR, ICMP, IP, send


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=["benign", "suspicious", "all", "burst"], default="all", nargs="?")
    args = parser.parse_args()
    target = socket.gethostbyname("target")
    def request(path="/", body=None):
        connection = http.client.HTTPConnection(target, 8080, timeout=3)
        connection.request("POST" if body else "GET", path, body=body,
                           headers={"Content-Type": "application/x-www-form-urlencoded"} if body else {})
        connection.getresponse().read()
        connection.close()
    def dns(name):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            client.sendto(bytes(DNS(id=44, qd=DNSQR(qname=name))), (target, 53))
            client.recvfrom(4096)
    if args.scenario in ("benign", "all"):
        for _ in range(3):
            request()
            dns("normal.lab.example")
            time.sleep(0.4)
        print(json.dumps({"scenario": "benign", "http_requests": 3, "dns_queries": 3}), flush=True)
    if args.scenario == "all":
        time.sleep(6)
    if args.scenario in ("suspicious", "all"):
        send(IP(dst=target)/ICMP(), count=1, verbose=False)
        request("/../../etc/passwd")
        request("/login", "username=fictional&password=not-a-real-secret")
        dns("blocked.lab.example")
        for port in range(10000, 10025):
            with socket.socket() as client:
                client.settimeout(0.2)
                client.connect_ex((target, port))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            for _ in range(40):
                client.sendto(b"LAB-BURST" * 20, (target, 9999))
                time.sleep(0.003)
        print(json.dumps({"scenario": "suspicious", "connectivity_checks": 1, "http_checks": 2, "dns_indicators": 1, "tcp_attempts": 25, "udp_packets": 40}), flush=True)
    if args.scenario == "burst":
        # A second independently generated burst exercises variable packet sizes.
        # It is demonstration traffic, not an addition to the frozen evaluation.
        # Start shortly after an event-window boundary so this short lab burst
        # stays within one feature window. Boundary splitting remains a limit.
        time.sleep((5 - time.time() % 5 + 0.1) % 5)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            for index in range(45):
                client.sendto(b"LAB-ONLY" * (5 + index * 7 % 30), (target, 9998))
                time.sleep(0.002 + index % 3 * 0.002)
        print(json.dumps({"scenario": "burst", "udp_packets": 45, "payload_bytes": "40–272 variable"}), flush=True)


if __name__ == "__main__":
    main()
