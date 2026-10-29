from dataclasses import replace

from ids_lab.packets import Packet
from ids_lab.rules import Rules


def tcp(timestamp=100, flags=16, seq=101, payload=b"", sport=12000):
    return Packet(timestamp,"192.0.2.2","198.51.100.4",sport,8080,"tcp",40+len(payload),flags,seq,payload)


def test_syn_threshold_positive_negative_and_expiry():
    engine=Rules()
    for index in range(10):
        assert "CUSTOM-002" not in engine.inspect(tcp(timestamp=100+index*.1,flags=2))
    assert "CUSTOM-002" in engine.inspect(tcp(timestamp=101.1,flags=2))
    assert "CUSTOM-002" not in engine.inspect(tcp(timestamp=110,flags=2))


def test_dns_indicator_exact_match_and_echo_is_informational():
    engine=Rules()
    dns=Packet(100,"192.0.2.2","198.51.100.4",123,53,"udp",80,dns_name="blocked.lab.example")
    assert engine.inspect(dns)==["CUSTOM-005"]
    assert engine.inspect(replace(dns,dns_name="notblocked.lab.example"))==[]
    assert engine.inspect(replace(dns,dns_name="normal.lab.example"))==[]
    assert engine.inspect(replace(dns,echo_request=True,dns_name=""))==["CUSTOM-001"]
    assert engine.config["rules"]["CUSTOM-001"]["severity"]==4


def test_traversal_reassembly_out_of_order_and_retransmission():
    engine=Rules()
    engine.inspect(tcp(flags=2,seq=100))
    request=b"GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: lab.example\r\n\r\n"
    assert engine.inspect(tcp(seq=121,payload=request[20:]))==[]
    assert engine.inspect(tcp(seq=101,payload=request[:20]))==["CUSTOM-004"]
    assert engine.inspect(tcp(seq=101,payload=request))==[]


def test_credential_field_requires_http_post_and_complete_body():
    engine=Rules()
    body=b"username=fake&password=fake"
    header=b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: "+str(len(body)).encode()+b"\r\n\r\n"
    assert engine.inspect(tcp(payload=header))==[]
    assert engine.inspect(tcp(seq=101+len(header),payload=body))==["CUSTOM-003"]
    other=Rules()
    assert other.inspect(tcp(payload=b"GET /password=normal HTTP/1.1\r\n\r\n"))==[]


def test_normal_http_and_tls_bytes_do_not_match_http_rules():
    assert Rules().inspect(tcp(payload=b"GET /welcome HTTP/1.1\r\nHost: lab.example\r\n\r\n"))==[]
    assert Rules().inspect(tcp(payload=b"\x16\x03\x03encrypted password=fake ../"))==[]


def test_tcp_stream_memory_and_count_are_bounded():
    engine=Rules()
    engine.inspect(tcp(payload=b"x"*65000))
    engine.inspect(tcp(seq=65101,payload=b"x"*1000))
    assert engine.stream_drops==1
    for index in range(150):
        engine.inspect(tcp(sport=20000+index,payload=b"G"))
    assert len(engine.streams)<=128
