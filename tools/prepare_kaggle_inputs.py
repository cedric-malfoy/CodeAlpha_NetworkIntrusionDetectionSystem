"""Package allowlisted offline inputs for private Kaggle runs with no network."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def build(output, owner, raw, wheels):
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError('Build the pinned portable runtime with Python 3.12')
    output.mkdir(parents=True, exist_ok=True)
    prefix = Path(sys.base_prefix)
    runtime = output/'python-runtime.tar.gz'
    with tarfile.open(runtime, 'w:gz') as archive:
        archive.add(prefix/'bin/python3.12', arcname='python/bin/python3.12', recursive=False)
        for path in sorted((prefix/'lib/python3.12').rglob('*')):
            relative = path.relative_to(prefix)
            if path.is_file() and 'site-packages' not in relative.parts and '__pycache__' not in relative.parts:
                archive.add(path, arcname=str(Path('python')/relative), recursive=False)
    with tarfile.open(output/'wheels.tar.gz', 'w:gz') as archive:
        for path in sorted(wheels.glob('*.whl')):
            archive.add(path, arcname='wheels/'+path.name, recursive=False)
    with tarfile.open(output/'captures.tar.gz', 'w:gz') as archive:
        for path in sorted(raw.rglob('*')):
            if path.is_file() and not path.name.endswith('.part'):
                archive.add(path, arcname=str(Path('raw')/path.relative_to(raw)), recursive=False)
    license_path = output/'PYTHON-LICENSE.txt'
    with urllib.request.urlopen('https://raw.githubusercontent.com/python/cpython/v3.12.14/LICENSE', timeout=60) as response:
        license_path.write_bytes(response.read())
    (output/'SOURCE-NOTICES.md').write_text((ROOT/'SOURCES.md').read_text() +
        '\n\nOffline research environment: CPython 3.12.14 and the pinned project wheel distributions. '
        'Original Python license is included; wheel distributions retain their own license metadata. '
        'IoT-23 capture and label sources are identified in the accompanying manifest. '
        'This input dataset is staged privately for reproducible computation.\n')
    files = {p.name: {'sha256':sha(p),'bytes':p.stat().st_size} for p in output.glob('*.tar.gz')}
    manifest = {'dataset':f'{owner}/signalwatch-offline-research-inputs', 'python':sys.version,
                'archives':files, 'raw_files':{str(p.relative_to(raw)): {'sha256':sha(p),'bytes':p.stat().st_size}
                                             for p in sorted(raw.rglob('*')) if p.is_file() and not p.name.endswith('.part')},
                'source_manifest':json.loads((ROOT/'data/sources.json').read_text()),
                'fresh_manifest':json.loads((ROOT/'research/protocol.json').read_text())['fresh_captures']}
    (output/'input_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (output/'dataset-metadata.json').write_text(json.dumps({'id':manifest['dataset'],
        'title':'Signalwatch offline research inputs', 'licenses':[{'name':'other'}],
        'description':'Private reproducibility inputs for the Signalwatch false-alarm study. Includes the CPython 3.12 runtime, original dependency wheels with their license metadata, and selected public IoT-23 packet captures and connection labels. Sources and SHA-256 hashes are recorded in input_manifest.json; attribution and license notices are retained in SOURCE-NOTICES.md and PYTHON-LICENSE.txt. Mixed third-party components retain their original licenses. No credentials or malware executables are included.'},indent=2)+'\n')
    print(json.dumps({'dataset':manifest['dataset'],'archive_bytes':sum(x['bytes'] for x in files.values())},indent=2))


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner',required=True)
    parser.add_argument('--raw',type=Path,required=True)
    parser.add_argument('--wheels',type=Path,default=ROOT/'artifacts/kaggle/wheels')
    parser.add_argument('--output',type=Path,default=ROOT/'artifacts/kaggle/inputs')
    args=parser.parse_args()
    build(args.output,args.owner,args.raw,args.wheels)
