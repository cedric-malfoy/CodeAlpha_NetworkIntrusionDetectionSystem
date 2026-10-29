"""Owned temporary dashboard fixture with isolated synthetic incidents."""
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from threading import Thread

from werkzeug.serving import make_server

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from ids_lab.engine import replay
from ids_lab.rules import load_rules
from ids_lab.store import Store
from ids_lab.web import create_app
from tools.make_demo import main as generate


def insert(path,identity,source):
    store=Store(path)
    store.alert('browser',{'flow_id':identity,'first':1700000150,'last':1700000151,'src':source,
                          'dst':'198.51.100.10','sport':1000,'dport':80,'protocol':'tcp'},
                ['CUSTOM-004'],True,0.99,load_rules())
    store.close()


def main():
    with TemporaryDirectory(prefix='custom-ids-browser-') as directory:
        path=Path(directory)/'ids.sqlite3'
        replay(ROOT/'examples/scenarios.pcap',path)
        insert(path,'xss-test','<script>window.pwned=true</script>')
        server=make_server('127.0.0.1',0,create_app(path),threaded=True)
        thread=Thread(target=server.serve_forever,daemon=True);thread.start()
        print(json.dumps({'url':f'http://127.0.0.1:{server.server_port}'}),flush=True)
        try:
            for line in sys.stdin:
                if line.strip()=='add':insert(path,'new-event','192.0.2.250')
        finally:
            server.shutdown();server.server_close();thread.join(timeout=5)


if __name__=='__main__':main()
