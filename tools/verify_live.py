"""Verify successive live traffic batches against the already-built local Docker lab."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
OPENER=urllib.request.build_opener(urllib.request.ProxyHandler({}))


def api(name):
    # Only loopback lab API requests bypass proxies, never external destinations.
    with OPENER.open('http://127.0.0.1:8088/api/'+name,timeout=10) as response:
        return json.load(response)


def main():
    subprocess.run(['docker','compose','up','-d','--no-build'],cwd=ROOT,check=True)
    for _ in range(60):
        try:
            before=api('status')
            if before['capture_active']:break
        except (OSError,ValueError):pass
        time.sleep(.5)
    else:raise RuntimeError('Live capture did not become ready')
    initial_run=before['state']['sensor']['run_id']
    started=time.time()
    observations=[]
    for scenario in ['benign','suspicious','burst']:
        case_start=time.time()
        result=subprocess.run(['docker','compose','run','--rm','traffic',scenario],cwd=ROOT,capture_output=True,text=True,check=True,timeout=60)
        time.sleep(6)
        status=api('status')
        assert status['capture_active']
        assert status['state']['sensor']['run_id']==initial_run,'Sensor restarted during continuous-capture verification'
        events=[entry for entry in api('alerts?limit=500')['alerts'] if entry['run_id']==initial_run and entry['timestamp']>=case_start]
        observations.append({'scenario':scenario,'generator_output':result.stdout.strip(),'events':len(events),
                             'rules':sorted({rule for entry in events for rule in entry['rule_ids']}),
                             'ml_flags':sum(bool(entry['ml']) for entry in events),'scores':[entry['score'] for entry in events if entry['ml']]})
        print(json.dumps(observations[-1]),flush=True)
    assert not observations[0]['rules'],'Benign control unexpectedly matched a custom rule'
    assert set(observations[1]['rules'])=={f'CUSTOM-00{index}' for index in range(1,6)}
    assert observations[2]['ml_flags']>0,'Variable-size burst did not demonstrate a live ML alert'
    final=api('status')
    image=subprocess.check_output(['docker','image','inspect','codealpha-custom-ids:local','--format','{{.Id}}'],cwd=ROOT,text=True).strip()
    evidence={'generated_at_utc':datetime.now(timezone.utc).isoformat(),'continuous_same_run_verified':True,
              'duration_seconds':time.time()-started,'image_id':image,'cases':observations,'final_status':final,
              'note':'Demonstration outcomes are not held-out benchmark metrics. Live fixed-size traffic may not be flagged by ML. Variable-size burst is a separate documented supported demonstration.'}
    directory=ROOT/'reports/evidence';directory.mkdir(parents=True,exist_ok=True)
    (directory/'live_capture.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print('Live capture, all five rules, and ML demonstration verified without restarting the sensor.')


if __name__=='__main__':main()
