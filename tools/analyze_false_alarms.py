"""Descriptive error audit of the reproduced baseline; does not fit a policy."""
import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd


def row_keys(values):
    values = np.ascontiguousarray(values, dtype=np.float64).copy()
    values[values == 0] = 0  # Treat positive and negative zero identically.
    return values.view(np.dtype((np.void, values.dtype.itemsize * values.shape[1]))).ravel()


def analyze(output):
    records = json.loads((output/'data/index.json').read_text())['captures']
    positives = []
    for r in records:
        if r['split'] == 'train':
            with np.load(output/'data'/f"{r['id']}.npz",allow_pickle=False) as a:
                positives.append(a['X'][a['y'] == 1])
    reference = row_keys(np.concatenate(positives))
    findings = []
    for r in records:
        if r['split'] != 'test' or r['domain'] != 'public':
            continue
        predictions = pd.read_csv(output/'predictions/baseline'/f"{r['id']}.csv.gz",usecols=['window_id','validation_f1__ml'])
        with np.load(output/'data'/f"{r['id']}.npz",allow_pickle=False) as a:
            assert np.array_equal(predictions.window_id.to_numpy(), a['window_id'])
            false_positive = (a['y'] == 0) & (predictions.validation_f1__ml.to_numpy() == 1)
            matches = int(np.isin(row_keys(a['X'][false_positive]),reference).sum())
            findings.append({'capture':r['id'], 'false_positives':int(false_positive.sum()),
                             'exact_malicious_training_feature_matches':matches,
                             'false_positives_by_protocol':{str(p):int(np.sum(false_positive & (a['protocol']==p))) for p in np.unique(a['protocol'])}})
    total = sum(r['false_positives'] for r in findings)
    overlap = sum(r['exact_malicious_training_feature_matches'] for r in findings)
    result = {'scope':'Exploratory published-test error audit; no fresh-data labels or scores used to select a policy.',
              'diagnostic_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'total_false_positives':total,'exact_training_positive_feature_matches':overlap,
              'exact_match_fraction':overlap/total if total else None,'captures':findings}
    (output/'error_analysis.json').write_text(json.dumps(result,indent=2)+'\n')
    text = ['# Baseline false-alarm diagnosis','',
            f'The reproduced public test contains **{total:,} false-positive windows**. Of these, **{overlap:,}** have feature vectors identical to at least one maliciously labeled training window.',
            '', '| Capture | False positives | Exact matches to malicious training vectors |', '|---|---:|---:|']
    text.extend(f"| {r['capture']} | {r['false_positives']:,} | {r['exact_malicious_training_feature_matches']:,} |" for r in findings)
    text += ['', 'Protocol counts and exact matching details are in `error_analysis.json`.', '',
             'This is evidence of ambiguity in the current representation relative to the published labels. '
             'A deterministic classifier using only these features assigns identical scores to identical vectors. '
             'Changing its cutoff can trade false positives against missed positives, but cannot distinguish the paired vectors. '
             'This does not prove that all false alarms have this cause, that the source labels are perfect, or that the result generalizes beyond these captures.', '',
             'The next research question is whether independently validated context or a better evaluation unit can resolve this ambiguity. '
             'That requires new development data and another reserved evaluation set; the already inspected fresh results must not become a repeatedly tuned test.', '']
    (output/'ERROR_ANALYSIS.md').write_text('\n'.join(text))
    print(json.dumps(result,indent=2))


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    analyze(parser.parse_args().output.resolve())
