"""Scientific accounting and experimental isolation regressions."""
import json
from pathlib import Path

import numpy as np
import pytest

from ids_lab.features import Extractor
from ids_lab.labels import LabelIndex
from ids_lab.packets import decode
from ids_lab.synthetic import session
from research.common import Deadline, digest, protected_hashes, write_json
from research.data import DetailedLabels, extract, load
from research.evaluation import budget_threshold, decisions, incident_index, incident_metrics, metrics
from research.runner import matrix


def test_budget_selection_keeps_ties_together_and_can_abstain():
    y = np.array([1, 0, 1, 0])
    scores = np.array([.9, .9, .8, .1])
    policy = budget_threshold(y, scores, 0)
    assert policy['all_negative'] and policy['validation_recall'] == 0
    assert not np.any(scores >= policy['threshold'])
    policy = budget_threshold(y, scores, .5)
    assert policy['threshold'] == .8
    assert policy['validation_recall'] == 1
    assert metrics(y, scores >= policy['threshold'])['false_positive_rate'] <= .5


def test_missing_validation_class_is_explicitly_infeasible():
    assert budget_threshold(np.zeros(3), np.array([.1, .2, .3]), .01)['threshold'] is None
    result = metrics(np.array([0, 0, -1]), np.array([False, True, True]))
    assert result['recall'] is None and result['balanced_accuracy'] is None
    assert result['samples'] == 2 and result['unknown_windows'] == 1 and result['unknown_alerts'] == 1


def test_intrusion_metrics_exclude_non_intrusion_rule_semantics():
    mask = np.array([1, 2, 4, 8, 16, 0])
    output = decisions(mask, np.array([0, 0, 0, 0, 0, 1]), .95)
    assert output['rules'].tolist() == [False, True, False, True, False, False]
    assert output['union'].tolist() == [False, True, False, True, False, True]
    assert output['ml'].tolist() == [False, False, False, False, False, True]


def test_incident_accounting_does_not_call_mixed_or_unknown_groups_false():
    g = {'src': np.array(['a']*6), 'dst': np.array(['b']*6), 'first': np.array([1, 2, 61, 62, 121, 122]),
         'y': np.array([0, 0, 0, 1, 0, -1]), 'label_uid': np.array(['a', 'b', 'c', 'd', 'e', '']),
         'connection_id': np.array(['x']*6)}
    result = incident_metrics(g, np.ones(6, dtype=bool), incident_index(g))
    assert result['incidents'] == 3 and result['pure_benign_incidents'] == 1
    assert result['mixed_or_unknown_incidents'] == 2
    assert result['malicious_connection_recall'] == 1


def test_detailed_label_join_preserves_runtime_boundaries_and_subtype(tmp_path):
    from ids_lab.packets import connection_key
    labels = tmp_path/'labels.log'
    labels.write_text('100 uid42 192.0.2.2 1000 198.51.100.4 80 tcp http 2 0 0 SF - - 0 S 1 40 0 0 - Malicious C&C\n')
    detailed, original = DetailedLabels(labels), LabelIndex(labels)
    for end in (101, 103, 103.01):
        window = {'connection': connection_key('tcp','192.0.2.2',1000,'198.51.100.4',80), 'first': 100.1, 'last': end}
        label, reason, uid, subtype = detailed.describe(window)
        old_label, old_reason = original.match(window)
        assert (None if label == -1 else label, reason) == (old_label, old_reason)
        if label == 1:
            assert uid == 'uid42' and subtype == 'C&C'


def test_research_extraction_matches_runtime_and_keeps_unknown_windows():
    packets, labels = session(100, 1700100000)
    runtime = Extractor()
    expected = []
    for raw in packets:
        expected.extend(runtime.push(decode(raw)))
    expected.extend(runtime.finish())
    arrays, counts = extract(packets, lambda w: (-1, 'unmatched', '', ''), Deadline())
    np.testing.assert_array_equal(arrays['X'], np.array([w['values'] for w in expected]))
    assert len(arrays['y']) == counts['unmatched'] == len(expected)
    assert np.all(arrays['y'] == -1)
    assert len(arrays['rule_mask']) == len(expected)


def test_training_matrix_never_reads_test_or_fresh_features():
    groups = {name: {'record': {'split': name, 'domain': 'public'}, 'X': np.array([[value]*22]), 'y': np.array([1])}
              for name, value in [('train', 1), ('validation', 2), ('test', 3), ('fresh', 4)]}
    x, y = matrix(groups, 'train')
    assert x.shape == (1, 22) and np.all(x == 1)


def test_public_capture_preparation_records_domain_and_matches_labels(tmp_path, monkeypatch):
    from scapy.all import Ether, IP, TCP
    import research.data as data
    (tmp_path/'data').mkdir()
    write_json(tmp_path/'data/sources.json', {'captures': [{'id':'one','pcap':'one.pcap','split':'train'}]})
    labels = tmp_path/'labels.log'
    labels.write_text('100 uid 192.0.2.2 1000 198.51.100.4 80 tcp http 2 0 0 SF - - 0 S 1 40 0 0 - Benign -\n')
    files = {'one/one.pcap': {'sha256':'fixture','path':'fixture'},
             'one/conn.log.labeled': {'sha256':digest(labels),'path':str(labels)}}
    raw = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02')/IP(src='192.0.2.2',dst='198.51.100.4')/TCP(sport=1000,dport=80)
    raw.time = 100.1
    monkeypatch.setattr(data, 'ROOT', tmp_path)
    monkeypatch.setattr(data, 'fetch', lambda *args: files)
    monkeypatch.setattr(data, 'read_pcap', lambda _: iter([raw]))
    monkeypatch.setattr(data, 'lab_sessions', lambda: [])
    records = data.prepare(tmp_path/'out', 'fixture', Deadline())
    assert records[0]['domain'] == 'public'
    assert records[0]['benign'] == 1
    assert data.load(tmp_path/'out')['one']['record']['domain'] == 'public'


def test_corrupt_cache_is_rejected(tmp_path):
    path = tmp_path/'data'
    path.mkdir()
    array = path/'one.npz'
    np.savez_compressed(array, X=np.zeros((1, 22)), y=np.array([0]))
    write_json(path/'index.json', {'captures': [{'id':'one','array_sha256':digest(array)}]})
    array.write_bytes(b'corrupt')
    with pytest.raises(ValueError, match='corrupted'):
        load(tmp_path)


def test_atomic_json_checkpoint_and_published_files_are_preserved(tmp_path):
    before = protected_hashes()
    target = tmp_path/'checkpoint.json'
    write_json(target, {'status':'complete'})
    assert json.loads(target.read_text()) == {'status':'complete'}
    assert not target.with_suffix('.json.tmp').exists()
    assert protected_hashes() == before
