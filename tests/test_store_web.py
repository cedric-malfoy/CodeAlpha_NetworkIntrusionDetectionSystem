import json
import time

from ids_lab.rules import load_rules
from ids_lab.store import Store, connect_readonly, query_events, summary
from ids_lab.web import create_app


def sample(timestamp=100):
    return {'flow_id':'fixed-flow','first':timestamp,'last':timestamp+1,'src':'192.0.2.2','dst':'198.51.100.4','sport':1000,'dport':80,'protocol':'tcp'}


def test_rule_and_ml_merge_idempotently_and_survive_restart(tmp_path):
    path=tmp_path/'ids.sqlite3'
    store=Store(path)
    store.alert('run',sample(),['CUSTOM-004'],False,None,load_rules())
    store.close()
    store=Store(path)
    store.alert('run',sample(),[],True,0.99,load_rules())
    store.alert('run',sample(),[],True,0.99,load_rules())
    store.close()
    with connect_readonly(path) as db:
        result=query_events(db)
        assert len(result)==1 and result[0]['detector']=='Both'
        assert result[0]['severity']==1
        assert summary(db)['incidents']==1


def test_incidents_aggregate_source_destination_in_60_second_buckets(tmp_path):
    path=tmp_path/'ids.sqlite3';store=Store(path)
    for index,timestamp in enumerate([61,62,121]):
        store.alert('run',{**sample(timestamp),'flow_id':str(index)},['CUSTOM-002'],False,None,load_rules())
    store.close()
    with connect_readonly(path) as db:
        assert summary(db)['events']==3 and summary(db)['incidents']==2


def test_cold_dashboard_and_empty_database_are_usable(tmp_path):
    path=tmp_path/'ids.sqlite3'
    app=create_app(path);client=app.test_client()
    assert client.get('/').status_code==200
    assert client.get('/api/status').json['events']==0
    path.touch()
    assert client.get('/api/alerts').json['alerts']==[]


def test_api_filters_limits_and_readonly_contract(tmp_path):
    path=tmp_path/'ids.sqlite3';store=Store(path)
    store.alert('run',sample(),['CUSTOM-004'],True,0.99,load_rules());store.close()
    client=create_app(path).test_client()
    assert len(client.get('/api/alerts?severity=1&detector=Both&source=192.0.2.2').json['alerts'])==1
    assert client.get('/api/alerts?severity=2').json['alerts']==[]
    assert client.get('/api/alerts?source=%27%20OR%201=1--').json['alerts']==[]
    for query in ['severity=10','limit=abc','detector=bad','rule=unknown']:
        assert client.get('/api/alerts?'+query).status_code==400
    assert client.post('/api/alerts').status_code==405
    assert client.get('/api/incidents').json['incidents'][0]['count']==1
    assert client.get('/api/model').json['model_version']=='custom-rf-v1'


def test_stale_live_capture_is_distinguishable_from_no_alerts(tmp_path):
    path=tmp_path/'ids.sqlite3';store=Store(path)
    store.state('sensor',{'mode':'live','status':'active','heartbeat':time.time()-60});store.close()
    status=create_app(path).test_client().get('/api/status').json
    assert status['sensor_stale'] is True and status['capture_active'] is False


def test_security_headers_and_source_values_are_data(tmp_path):
    path=tmp_path/'ids.sqlite3';store=Store(path)
    store.alert('run',{**sample(),'src':'<script>window.pwned=true</script>'},['CUSTOM-004'],False,None,load_rules());store.close()
    response=create_app(path).test_client().get('/api/alerts')
    assert response.content_type=='application/json'
    assert response.headers['X-Content-Type-Options']=='nosniff'
    assert response.json['alerts'][0]['src'].startswith('<script>')
