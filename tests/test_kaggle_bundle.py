"""The remote snapshot must be self-contained and private."""
import base64
import hashlib
import io
import json
import zipfile

import nbformat

from tools.prepare_kaggle import build


def test_private_notebook_bundle_contains_runtime_assets_and_verified_sources(tmp_path):
    build(tmp_path, 'example-owner', smoke=True)
    metadata = json.loads((tmp_path/'kernel-metadata.json').read_text())
    assert metadata['is_private'] is True and metadata['enable_gpu'] is False
    assert metadata['id'] == 'example-owner/signalwatch-false-alarm-smoke-check'
    notebook = nbformat.read(tmp_path/'signalwatch_research.ipynb', as_version=4)
    nbformat.validate(notebook)
    code = notebook.cells[1].source
    import ast
    tree = ast.parse(code)
    payload = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign) and
                   any(isinstance(t, ast.Name) and t.id == 'PAYLOAD' for t in node.targets))
    with zipfile.ZipFile(io.BytesIO(base64.b64decode(payload))) as bundle:
        names = set(bundle.namelist())
        assert {'config/rules.json', 'templates/dashboard.html', 'static/dashboard.js',
                'research/runner.py', 'tools/prepare_kaggle.py', 'models/detector.joblib', 'RESEARCH_SOURCE.json'} <= names
        assert not any('.venv' in name or 'access_token' in name or 'credentials' in name for name in names)
        manifest = json.loads(bundle.read('RESEARCH_SOURCE.json'))
        assert all(hashlib.sha256(bundle.read(name)).hexdigest() == expected for name, expected in manifest['files'].items())
    assert any('uv' in c.source and "'3.12'" in c.source for c in notebook.cells if c.cell_type == 'code')


def test_offline_notebook_pins_private_inputs_and_needs_no_external_downloads(tmp_path):
    manifest = tmp_path/'input_manifest.json'
    manifest.write_text(json.dumps({'dataset':'example-owner/offline-inputs','archives':{}}))
    build(tmp_path/'notebook', 'example-owner', smoke=True, dataset='example-owner/offline-inputs', input_manifest=manifest)
    metadata = json.loads((tmp_path/'notebook/kernel-metadata.json').read_text())
    assert metadata['enable_internet'] is False
    assert metadata['dataset_sources'] == ['example-owner/offline-inputs']
    notebook = nbformat.read(tmp_path/'notebook/signalwatch_research.ipynb',as_version=4)
    cell = notebook.cells[3].source
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() in cell
    assert '--no-index' in cell and "filter='data'" in cell
    assert 'uv' not in cell
