from pathlib import Path

from scapy.all import wrpcap

from ids_lab.engine import replay
from ids_lab.store import connect_readonly,query_events,summary
from tools.make_demo import captures


def test_real_pipeline_finds_five_signatures_and_replay_is_idempotent(tmp_path):
    path=tmp_path/'mixed.pcap';database=tmp_path/'ids.sqlite3'
    _,packets=captures();wrpcap(str(path),packets)
    replay(path,database)
    with connect_readonly(database) as db:
        events=query_events(db,limit=500)
        signatures={rule for event in events for rule in event['rule_ids']}
        assert signatures=={f'CUSTOM-00{number}' for number in range(1,6)}
        first=summary(db)['events']
    replay(path,database)
    with connect_readonly(database) as db: assert summary(db)['events']==first


def test_benign_fixture_has_no_custom_intrusion_rule_hits(tmp_path):
    path=tmp_path/'benign.pcap';database=tmp_path/'ids.sqlite3'
    packets,_=captures();wrpcap(str(path),packets)
    replay(path,database)
    with connect_readonly(database) as db:
        assert not any(event['rule_ids'] for event in query_events(db))


def test_rules_continue_operating_when_model_is_missing(tmp_path):
    path=tmp_path/'mixed.pcap';database=tmp_path/'ids.sqlite3'
    _,packets=captures();wrpcap(str(path),packets)
    replay(path,database,model_dir=tmp_path/'no-model')
    with connect_readonly(database) as db:
        assert summary(db)['state']['sensor']['model_status']=='unavailable'
        assert len({rule for event in query_events(db) for rule in event['rule_ids']})==5


def test_synthetic_capture_writing_never_resolves_network_addresses(tmp_path,monkeypatch):
    import scapy.layers.l2
    def forbidden(_address,**_kwargs):
        raise AssertionError('Synthetic generation attempted address resolution')
    monkeypatch.setattr(scapy.layers.l2,'getmacbyip',forbidden)
    _,packets=captures()
    wrpcap(str(tmp_path/'offline.pcap'),packets)
