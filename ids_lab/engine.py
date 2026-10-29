"""Our continuous capture/rule/feature/model/incident pipeline."""
import hashlib
import json
from pathlib import Path
import queue
import threading
import time
import uuid

from scapy.all import AsyncSniffer

from .features import Extractor, window_id
from .model import Model
from .packets import decode, read_pcap
from .rules import Rules, load_rules
from .store import Store


class Engine:
    def __init__(self, database, mode="replay", run_id=None, model_dir=None, rule_path=None, notify=False):
        self.store = Store(database)
        self.config = load_rules(rule_path)
        self.rules = Rules(self.config)
        self.extractor = Extractor()
        self.model = Model(model_dir)
        self.run_id = run_id or uuid.uuid4().hex
        self.mode, self.notify = mode, notify
        self.stats = {"packets": 0, "unsupported": 0, "windows": 0, "ml_suspicious": 0, "queue_dropped": 0}
        self.started = time.time()
        self.started_capture = False
        self.checkpoint("starting")

    def checkpoint(self, status="active"):
        self.store.state("sensor", {"status": status, "mode": self.mode, "run_id": self.run_id,
                                   "heartbeat": time.time(), "started": self.started,
                                   "model_status": self.model.status, "model_error": self.model.error,
                                   "model_version": self.model.metadata.get("model_version"),
                                   "threshold": self.model.metadata.get("threshold"),
                                   "late_packets": self.extractor.late, "flow_dropped": self.extractor.dropped,
                                   "stream_dropped": self.rules.stream_drops, **self.stats})

    def _record(self, window, rule_ids=(), score=None):
        suspicious = score is not None and score >= self.model.metadata["threshold"]
        result = self.store.alert(self.run_id, window, rule_ids, suspicious, score, self.config)
        if result and self.notify:
            print(json.dumps({"incident": result["incident_id"], "source": window["src"], "detector": result["detector"],
                              "rules": result["rules"], "model_score": result["score"]}), flush=True)

    def _windows(self, windows):
        if not windows:
            return
        self.stats["windows"] += len(windows)
        for window, score in zip(windows, self.model.scores(windows)):
            if score is not None and score >= self.model.metadata["threshold"]:
                self.stats["ml_suspicious"] += 1
            self._record(window, score=score)

    def feed(self, raw):
        self.stats["packets"] += 1
        packet = decode(raw)
        if packet is None:
            self.stats["unsupported"] += 1
            return
        self._windows(self.extractor.push(packet))
        findings = self.rules.inspect(packet)
        if findings:
            self._record({"flow_id": window_id(packet), "first": packet.timestamp, "last": packet.timestamp,
                          "src": packet.src, "dst": packet.dst, "sport": packet.sport,
                          "dport": packet.dport, "protocol": packet.protocol}, findings)
        if self.stats["packets"] % 1000 == 0:
            self.checkpoint()

    def finish(self, status="completed"):
        self._windows(self.extractor.finish())
        self.checkpoint(status)
        self.store.close()


def replay(pcap, database, model_dir=None, notify=False):
    path = Path(pcap)
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    engine = Engine(database, run_id="pcap-" + digest[:24], model_dir=model_dir, notify=notify)
    try:
        for raw in read_pcap(path):
            engine.feed(raw)
    except Exception:
        engine.finish("failed")
        raise
    engine.finish()
    return engine.stats


def live(interface, database, stop=None, model_dir=None):
    stop = stop or threading.Event()
    engine = Engine(database, mode="live", model_dir=model_dir, notify=True)
    pending = queue.Queue(maxsize=2048)
    def enqueue(packet):
        try:
            pending.put_nowait(packet)
        except queue.Full:
            engine.stats["queue_dropped"] += 1
    sniffer = AsyncSniffer(iface=interface, prn=enqueue, store=False,
                           started_callback=lambda: setattr(engine, "started_capture", True))
    status = "stopped"
    try:
        sniffer.start()
        deadline = time.monotonic() + 5
        while not engine.started_capture:
            if sniffer.exception:
                raise sniffer.exception
            if time.monotonic() > deadline:
                raise RuntimeError("Capture did not become ready; check interface and NET_RAW permission.")
            time.sleep(0.02)
        engine.checkpoint()
        last = time.monotonic()
        while not stop.is_set():
            try:
                engine.feed(pending.get(timeout=0.2))
            except queue.Empty:
                pass
            if time.monotonic() - last >= 1:
                engine._windows(engine.extractor.advance(time.time()))
                engine.checkpoint()
                last = time.monotonic()
            if not sniffer.running:
                raise RuntimeError("Capture stopped unexpectedly")
    except BaseException:
        status = "failed"
        raise
    finally:
        if sniffer.running:
            sniffer.stop()
        while not pending.empty():
            engine.feed(pending.get_nowait())
        engine.finish(status)
