"""Create a private, self-contained Kaggle notebook from an explicit source snapshot."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def build(output, owner, smoke=False, fresh=False, dataset=None, input_manifest=None):
    import nbformat
    patterns = ("ids_lab/*.py", "research/*.py", "research/*.json", "models/*", "config/*.json", "templates/*", "static/*", "data/sources*.json",
                "reports/*.json", "tests/test_*.py", "examples/*.pcap", "requirements*.txt", "pytest.ini", "tools/make_demo.py",
                "tools/prepare_data.py", "tools/train_model.py", "tools/prepare_kaggle.py", "tools/analyze_false_alarms.py")
    paths = sorted({p for pattern in patterns for p in ROOT.glob(pattern) if p.is_file()})
    if (ROOT / "RESEARCH_SOURCE.json").exists():
        origin = json.loads((ROOT / "RESEARCH_SOURCE.json").read_text())
    else:
        origin = {"commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                  "dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True))}
    source = {"commit": origin["commit"], "dirty": origin["dirty"],
              "files": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}}
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in paths:
            bundle.write(path, str(path.relative_to(ROOT)))
        bundle.writestr("RESEARCH_SOURCE.json", json.dumps(source, indent=2))
    raw = archive.getvalue()
    payload, checksum = base64.b64encode(raw).decode(), hashlib.sha256(raw).hexdigest()
    output.mkdir(parents=True, exist_ok=True)
    cells = [nbformat.v4.new_markdown_cell(
        "# Signalwatch: false-alarm research pilot\n\n"
        "This notebook runs the shared CPU research pipeline from a hash-verified source snapshot. "
        "Published-test comparisons are exploratory. Unknown labels remain excluded from detection denominators. "
        "The source model and published reports are preserved. No captured packets are transmitted.\n\n"
        f"Source commit: `{source['commit']}`; uncommitted snapshot: `{source['dirty']}`. "
        f"Mode: **{'synthetic software smoke check' if smoke else 'public-data research pilot'}**."),
        nbformat.v4.new_code_cell(
            "import base64, hashlib, io, json, os, pathlib, subprocess, sys, zipfile\n"
            "BASE = pathlib.Path('/kaggle/working') if pathlib.Path('/kaggle/working').exists() else pathlib.Path.cwd()\n"
            "WORK = pathlib.Path('/tmp/signalwatch') if pathlib.Path('/kaggle/working').exists() else BASE / '.signalwatch'\n"
            "WORK.mkdir(parents=True, exist_ok=True)\n"
            "PROJECT = WORK / 'signalwatch-source'\n"
            f"PAYLOAD = {payload!r}\n"
            "raw = base64.b64decode(PAYLOAD)\n"
            f"assert hashlib.sha256(raw).hexdigest() == {checksum!r}\n"
            "PROJECT.mkdir(parents=True, exist_ok=True)\n"
            "with zipfile.ZipFile(io.BytesIO(raw)) as bundle:\n"
            "    assert all(not pathlib.PurePosixPath(p).is_absolute() and '..' not in pathlib.PurePosixPath(p).parts for p in bundle.namelist())\n"
            "    bundle.extractall(PROJECT)\n"
            "snapshot = json.loads((PROJECT / 'RESEARCH_SOURCE.json').read_text())\n"
            "for filename, expected in snapshot['files'].items():\n"
            "    assert hashlib.sha256((PROJECT / filename).read_bytes()).hexdigest() == expected\n"
            "print('Verified source snapshot:', snapshot['commit'])"),
        nbformat.v4.new_markdown_cell("## Isolated environment\nPython 3.12 or newer and Internet access are required. "
            "The private environment avoids replacing the notebook runtime's NumPy or scikit-learn. Results go to the writable output folder."),
        nbformat.v4.new_code_cell(
            "subprocess.run([sys.executable, '-m', 'pip', 'install', '--quiet', 'uv==0.9.9'], check=True, timeout=300)\n"
            "ENV = WORK / 'signalwatch-env'\n"
            "PYTHON = ENV / 'bin/python'\n"
            "if not PYTHON.exists():\n"
            "    subprocess.run([sys.executable, '-m', 'uv', 'venv', '--python', '3.12', str(ENV)], check=True, timeout=600)\n"
            "subprocess.run([sys.executable, '-m', 'uv', 'pip', 'install', '--python', str(PYTHON), '--quiet', '-r', str(PROJECT / 'requirements-research.txt')], check=True, timeout=1200)\n"
            "OUTPUT = WORK / 'signalwatch-results'\n"
            "RUN_ENV = dict(os.environ, MPLCONFIGDIR=str(WORK / 'matplotlib-cache'), XDG_CACHE_HOME=str(WORK / 'cache'), OMP_NUM_THREADS='2', OPENBLAS_NUM_THREADS='2')\n"
            "def run_stage(stage):\n"
            f"    command = [str(PYTHON), '-m', 'research', stage, '--output', str(OUTPUT)] + {(['--smoke', '--seeds', '42'] if smoke else [])!r}\n"
            "    subprocess.run(command, cwd=PROJECT, env=RUN_ENV, check=True, timeout=14400)"),
        nbformat.v4.new_markdown_cell("## Prepare data and reproduce the baseline\nCapture and model checkpoints can be reused only with matching code, data and dependency fingerprints."),
        nbformat.v4.new_code_cell("run_stage('prepare')\nrun_stage('baseline')"),
        nbformat.v4.new_markdown_cell("## Compare detectors and validation-selected operating points\n"
            "Five model seeds are used in the full pilot. The prospective policy is RF seed 42 at a 0.1% validation false-positive budget; published-test results do not choose that policy."),
        nbformat.v4.new_code_cell("run_stage('compare')\nrun_stage('report')"),
    ]
    if dataset:
        if input_manifest is None:
            raise ValueError('Offline notebooks require --input-manifest to pin the attached inputs')
        input_spec = json.loads(input_manifest.read_text())
        if input_spec['dataset'] != dataset:
            raise ValueError('Input manifest dataset differs from --dataset')
        input_sha = hashlib.sha256(input_manifest.read_bytes()).hexdigest()
        cells[2].source = ('## Pinned offline environment\nThe attached private inputs supply Python 3.12, '
            'dependency wheels and packet captures. All archives are hash-verified before extraction. '
            'No external downloads are needed during execution.')
        cells[3].source = (
            "import tarfile\n"
            f"EXPECTED_INPUT_SHA = {input_sha!r}\n"
            "candidates = [p for p in pathlib.Path('/kaggle/input').rglob('input_manifest.json') if hashlib.sha256(p.read_bytes()).hexdigest() == EXPECTED_INPUT_SHA]\n"
            "assert len(candidates) == 1, 'Attach the exact private input dataset version used to build this notebook.'\n"
            "INPUT = candidates[0].parent\n"
            "inputs = json.loads(candidates[0].read_text())\n"
            "OUTPUT = WORK / 'signalwatch-results'\n"
            "OUTPUT.mkdir(parents=True, exist_ok=True)\n"
            "for name, details in inputs['archives'].items():\n"
            "    path = INPUT / name\n"
            "    with path.open('rb') as stream:\n"
            "        assert hashlib.file_digest(stream, 'sha256').hexdigest() == details['sha256']\n"
            "    with tarfile.open(path) as archive:\n"
            "        archive.extractall(OUTPUT if name == 'captures.tar.gz' else WORK, filter='data')\n"
            "PYTHON = WORK / 'python/bin/python3.12'\n"
            "subprocess.run([str(PYTHON), '-m', 'ensurepip', '--upgrade'], check=True, timeout=120)\n"
            "subprocess.run([str(PYTHON), '-m', 'pip', 'install', '--quiet', '--no-index', '--find-links', str(WORK / 'wheels'), '-r', str(PROJECT / 'requirements-research.txt')], check=True, timeout=1200)\n"
            "RUN_ENV = dict(os.environ, MPLCONFIGDIR=str(WORK / 'matplotlib-cache'), XDG_CACHE_HOME=str(WORK / 'cache'), OMP_NUM_THREADS='2', OPENBLAS_NUM_THREADS='2')\n"
            "def run_stage(stage):\n"
            f"    command = [str(PYTHON), '-m', 'research', stage, '--output', str(OUTPUT)] + {(['--smoke', '--seeds', '42'] if smoke else [])!r}\n"
            "    subprocess.run(command, cwd=PROJECT, env=RUN_ENV, check=True, timeout=14400)\n"
        )
    if fresh:
        cells.extend([nbformat.v4.new_markdown_cell("## Evaluate the frozen policy on fresh captures\nOnly runs after the baseline and comparison have frozen the candidate. Do not retune after viewing these results."),
                      nbformat.v4.new_code_cell("run_stage('evaluate-frozen')\nrun_stage('report')")])
    cells.extend([nbformat.v4.new_markdown_cell("## Downloadable evidence\nThe archive includes manifests, measured metrics, all-window prediction exports, plots and findings. "
                  "No API tokens, credential files, or dataset raw captures are included. Software checks and a successful run do not establish research novelty."),
                  nbformat.v4.new_code_cell(
                      "import shutil\n"
                      "subprocess.run([str(PYTHON), '-m', 'pytest', '-q'], cwd=PROJECT, env=RUN_ENV, check=True, timeout=600)\n"
                      "from IPython.display import Markdown, display\n"
                      "display(Markdown((OUTPUT / 'FINDINGS.md').read_text()))\n"
                      "export_dir = BASE / 'signalwatch-evidence'\n"
                      "export_dir.mkdir(exist_ok=True)\n"
                      "for path in OUTPUT.iterdir():\n"
                      "    if path.name in ('raw', 'data', 'fresh_data'):\n"
                      "        continue\n"
                      "    if path.is_dir():\n"
                      "        shutil.copytree(path, export_dir / path.name, dirs_exist_ok=True)\n"
                      "    else:\n"
                      "        shutil.copy2(path, export_dir / path.name)\n"
                      "print(shutil.make_archive(str(BASE / 'signalwatch-evidence'), 'zip', export_dir))")])
    notebook = nbformat.v4.new_notebook(cells=cells, metadata={"kernelspec": {"name": "python3", "display_name": "Python 3", "language": "python"}})
    nbformat.validate(notebook)
    nbformat.write(notebook, output / "signalwatch_research.ipynb")
    metadata = {"id": f"{owner}/signalwatch-false-alarm-{'smoke-check' if smoke else 'study'}", "title": f"Signalwatch false alarm {'smoke check' if smoke else 'study'}",
                "code_file": "signalwatch_research.ipynb", "language": "python", "kernel_type": "notebook",
                "is_private": True, "enable_gpu": False, "enable_tpu": False, "enable_internet": not bool(dataset),
                "dataset_sources": [dataset] if dataset else [], "competition_sources": [], "kernel_sources": []}
    (output / "kernel-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (output / "source_snapshot.json").write_text(json.dumps(source, indent=2) + "\n")
    print(f"Prepared private notebook: {metadata['id']} ({len(raw):,} bundled bytes)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/kaggle/pilot")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument("--dataset", help="Private offline input dataset owner/slug")
    parser.add_argument("--input-manifest", type=Path, help="Local manifest to pin exact offline input bytes")
    args = parser.parse_args()
    if args.smoke and args.fresh:
        parser.error("Smoke mode does not open fresh data")
    build(args.output, args.owner, args.smoke, args.fresh, args.dataset, args.input_manifest)
