"""Mock HTTP/DNS service: fixed responses, no authentication or filesystem reads."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import threading

from scapy.all import DNS, DNSRR


class Handler(BaseHTTPRequestHandler):
    def answer(self):
        body = b"Custom IDS lab server. Fictional traffic only.\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.answer()

    def do_POST(self):
        length = min(4096, max(0, int(self.headers.get("Content-Length", "0"))))
        self.rfile.read(length)
        self.answer()

    def log_message(self, *_args):
        pass


def dns():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("0.0.0.0", 53))
        while True:
            data, peer = server.recvfrom(4096)
            try:
                query = DNS(data)
                response = DNS(id=query.id, qr=1, aa=1, qd=query.qd,
                               an=DNSRR(rrname=query.qd.qname, rdata="192.0.2.10", ttl=30))
                server.sendto(bytes(response), peer)
            except (ValueError, AttributeError, IndexError):
                continue


if __name__ == "__main__":
    threading.Thread(target=dns, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
