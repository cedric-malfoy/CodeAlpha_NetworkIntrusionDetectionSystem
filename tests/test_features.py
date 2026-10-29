import math

import pytest
from scapy.all import Ether, ICMP, IP, IPv6, Raw, TCP, UDP

from ids_lab.features import Extractor, FEATURES
from ids_lab.packets import decode


def packet(timestamp=100.1, reverse=False, **kwargs):
    source, destination = ("198.51.100.4", "192.0.2.2") if reverse else ("192.0.2.2", "198.51.100.4")
    raw = Ether(src='02:00:00:00:00:20',dst='02:00:00:00:00:10')/IP(src=source, dst=destination)/TCP(sport=80 if reverse else 12345, dport=12345 if reverse else 80, **kwargs)
    raw.time = timestamp
    return raw


def test_known_bidirectional_counts_flags_and_ip_bytes():
    extractor = Extractor()
    for raw in (packet(flags="S"), packet(100.2, True, flags="SA"), packet(100.3, flags="A")):
        extractor.push(decode(raw))
    window = extractor.finish()[0]
    values = dict(zip(FEATURES, window["values"]))
    assert values["forward_packets"] == 2 and values["reverse_packets"] == 1
    assert values["forward_ip_bytes"] == 80 and values["reverse_ip_bytes"] == 40
    assert values["duration_s"] == pytest.approx(0.2)
    assert values["syn_ratio"] == pytest.approx(2/3)
    assert values["ack_ratio"] == pytest.approx(2/3)
    assert values["iat_mean"] == pytest.approx(0.1)
    assert values["source_connections"] == values["source_destination_ports"] == 1
    assert all(math.isfinite(value) for value in values.values())


def test_streamed_and_offline_feature_values_are_equal(tmp_path):
    from scapy.all import wrpcap
    from ids_lab.packets import read_pcap
    raw = [packet(100.1), packet(100.2, True), packet(106.0)]
    path = tmp_path / "sample.pcap"
    wrpcap(str(path), raw)
    def extract(packets):
        extractor, rows = Extractor(), []
        for item in packets:
            rows.extend(extractor.push(decode(item)))
        return rows + extractor.finish()
    direct, offline = extract(raw), extract(read_pcap(path))
    assert [value["values"] for value in direct] == [value["values"] for value in offline]
    assert [value["flow_id"] for value in direct] == [value["flow_id"] for value in offline]


def test_windows_close_at_event_time_and_idle_flush():
    extractor = Extractor()
    assert extractor.push(decode(packet(104.9))) == []
    assert len(extractor.advance(105)) == 1
    assert extractor.advance(106) == []
    extractor.push(decode(packet(104.99)))
    assert extractor.late == 1 and extractor.finish() == []


def test_flow_capacity_is_bounded():
    extractor = Extractor(max_flows=1)
    extractor.push(decode(packet()))
    raw = Ether()/IP(src="192.0.2.3", dst="198.51.100.4")/UDP(sport=1,dport=53)
    raw.time = 100.2
    extractor.push(decode(raw))
    assert extractor.dropped == 1 and len(extractor.flows) == 1


def test_payload_identity_does_not_enter_model_features():
    first, second = packet(), packet()
    first /= Raw(b"normal.test")
    second /= Raw(b"attack.test")
    one, two = Extractor(), Extractor()
    one.push(decode(first)); two.push(decode(second))
    assert one.finish()[0]["values"] == two.finish()[0]["values"]
    assert not any(name in FEATURES for name in ("source_ip", "label", "capture_id", "raw_port", "rule_result"))


@pytest.mark.parametrize("raw", [Ether()/IPv6(src="2001:db8::1",dst="2001:db8::2")/UDP(sport=1,dport=53), Ether()/IP()/ICMP()])
def test_ipv6_and_icmp_supported(raw):
    assert decode(raw) is not None


def test_non_ip_and_fragmented_packets_are_explicitly_unsupported():
    assert decode(Ether()/Raw(b"arbitrary")) is None
    assert decode(Ether()/IP(flags="MF")/UDP()) is None
