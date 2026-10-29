"""Capture final verification against an immutable source commit."""
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def main():
    output=ROOT/'reports/evidence';output.mkdir(parents=True,exist_ok=True)
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    files=subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0')
    fingerprints={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in files if name and not name.startswith('reports/')}
    commands=[
        ('python_tests',[sys.executable,'-m','pytest','-v','--tb=short']),
        ('browser_tests',['npm','run','test:browser']),
        ('dependencies',[sys.executable,'-m','pip_audit','-r','requirements-dev.txt','--no-deps','--disable-pip','--strict','--cache-dir',str(ROOT/'artifacts/pip-audit-cache'),'--progress-spinner','off','-f','json','-o',str(output/'dependency_audit.json')]),
    ]
    results=[]
    for name,command in commands:
        print(f'Checking {name}...',flush=True)
        try:
            result=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=240)
            exit_code=result.returncode
            transcript=result.stdout+'\n'+result.stderr
        except subprocess.TimeoutExpired:
            exit_code=124;transcript='Check timed out; not a passing result.'
        (output/(name+'.txt')).write_text(transcript.replace(str(ROOT),'<project>').rstrip()+'\n')
        results.append({'name':name,'command':['python' if part==sys.executable else part.replace(str(ROOT),'<project>') for part in command],'exit_code':exit_code,'passed':exit_code==0})
        print(f'{name}: exit {exit_code}',flush=True)
    verification={'generated_at_utc':datetime.now(timezone.utc).isoformat(),'source_commit':commit,
                  'python':platform.python_version(),'versions':{name:version(name) for name in ['scapy','numpy','scikit-learn','Flask','joblib','pytest','pip-audit','reportlab']},
                  'source_sha256':fingerprints,'checks':results,
                  'live_evidence':'live_capture.json records a separate real capture run using the recorded image. Node/Playwright tooling is pinned in package-lock.json.'}
    (output/'verification.json').write_text(json.dumps(verification,indent=2)+'\n')
    return 0 if all(item['passed'] for item in results) else 1


if __name__=='__main__':raise SystemExit(main())
