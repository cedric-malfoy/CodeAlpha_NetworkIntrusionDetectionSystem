import json
from pathlib import Path

import pytest

from ids_lab.features import FEATURES, Extractor
from ids_lab.labels import LabelIndex
from ids_lab.model import Model
from ids_lab.packets import Packet, connection_key


def test_label_join_rejects_unknown_and_ambiguous_connections(tmp_path):
    path=tmp_path/'labels.log'
    def line(label):
        return f"100 uid 192.0.2.2 1000 198.51.100.4 80 tcp http 2 0 0 SF - - 0 S 1 40 0 0 - {label} -\n"
    path.write_text('#fields ignored\n'+line('Benign'))
    index=LabelIndex(path)
    window={"connection":connection_key('tcp','192.0.2.2',1000,'198.51.100.4',80),'first':100.1,'last':101}
    assert index.match(window)==(0,'matched')
    assert index.match({**window,'last':110})==(None,'unmatched')
    path.write_text(line('Benign')+line('Malicious'))
    assert LabelIndex(path).match(window)==(None,'ambiguous')


def test_frozen_capture_and_session_partitions_are_disjoint():
    sources=json.loads(Path('data/sources.json').read_text())
    ids=[entry['directory'] for entry in sources['captures']]
    assert len(ids)==len(set(ids))
    from ids_lab.synthetic import lab_sessions
    groups={}
    for split,group,_packets,_labels in lab_sessions():
        assert group not in groups
        groups[group]=split


def test_shipped_model_is_compatible_and_inference_is_deterministic():
    model=Model()
    assert model.status=='ready',model.error
    extractor=Extractor()
    extractor.push(Packet(100,'192.0.2.2','198.51.100.4',12000,80,'tcp',40,2))
    windows=extractor.finish()
    assert model.scores(windows)==model.scores(windows)
    assert 0<=model.scores(windows)[0]<=1
    assert model.metadata['features']==list(FEATURES)


def test_missing_and_incompatible_models_are_explicitly_unavailable(tmp_path):
    assert Model(tmp_path).status=='unavailable'
    metadata=json.loads(Path('models/metadata.json').read_text())
    metadata['schema']='wrong-schema'
    (tmp_path/'metadata.json').write_text(json.dumps(metadata))
    model=Model(tmp_path)
    assert model.status=='unavailable' and 'schema' in model.error.lower()


def test_altered_model_hash_is_rejected_before_loading(tmp_path):
    metadata=json.loads(Path('models/metadata.json').read_text())
    (tmp_path/'metadata.json').write_text(json.dumps(metadata))
    (tmp_path/'detector.joblib').write_bytes(b'not a model')
    assert 'hash' in Model(tmp_path).error.lower()


def test_nonfinite_feature_vector_is_rejected():
    with pytest.raises(ValueError):
        Model().scores([{'values':[float('nan')]*len(FEATURES)}])
