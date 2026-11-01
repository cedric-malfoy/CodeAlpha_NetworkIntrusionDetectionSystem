# False-alarm research pilot

This research branch investigates false alarms in Signalwatch. It preserves the application model and published evidence. It does not claim a new detection algorithm or publication readiness.

The [first completed pilot and its measured outcome](RESULTS.md) are available, including the unsuccessful cutoff experiment and the feature-ambiguity diagnosis.

## Run locally

Use Python 3.12 and a virtual environment:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-research.txt
.venv/bin/python -m research run --smoke --seeds 42 --output artifacts/research/smoke
.venv/bin/python -m research run --output artifacts/research/pilot
```

The smoke run uses three generated sessions. It verifies software behavior and is not detection-accuracy evidence. The full run reproduces the published public/lab partitions, then compares four classifiers and five seeds. The current public downloads total about 100 MB.

The individual commands are `prepare`, `baseline`, `compare`, `evaluate-frozen`, and `report`. `run` executes the first three and the report. The prospective check is explicit:

```bash
.venv/bin/python -m research evaluate-frozen --output artifacts/research/pilot
.venv/bin/python -m research report --output artifacts/research/pilot
```

Fresh evaluation uses whole IoT-23 captures 1-1 and 34-1. Raw and label downloads are limited to 1 GiB total and 256 MiB per file. Source labels and supported-window coverage are audited; coverage below 90% stops interpretation. The input locations and scientific defaults are fixed in `protocol.json`.

## Operating points and accounting

- The original RF recipe is reproduced exactly, including its validation-F1 threshold grid. Every saved partition confusion matrix must match before comparison.
- The alternatives are standardized logistic regression (`C=1`, balanced classes, 2,000 iterations), a balanced decision tree (depth 10, minimum leaf 5), and histogram gradient boosting (200 iterations, 31 leaves, learning rate 0.1, balanced classes, no early stopping). RF uses the published settings.
- Seeds are 42–46. RF/tree/boosting seed variation is reported; repeating a deterministic estimator is not independent evidence.
- Additional thresholds maximize validation recall subject to public-validation FPR budgets of 0.1%, 0.5%, and 1%. Ties favor lower FPR and then higher cutoffs. A cutoff above one represents an all-negative policy; its zero recall is explicit. Missing validation classes make a budget infeasible.
- All supported windows are stored, including unknown labels. Only known labels enter detection denominators. Excluded packets, late/capacity drops, orphan rule events, and invalid labels remain coverage evidence.
- Primary rule/ML comparisons use SYN-burst and traversal rules (CUSTOM-002/004). ICMP, cleartext credentials, and the artificial DNS indicator retain separate event semantics. The original full event union remains in prediction exports.
- The comparison unit is the bidirectional five-second feature window. The incident count uses the existing source/destination/60-second grouping. Pure-benign incidents contain only known benign windows. Mixed and unknown groups are not counted as confirmed false incidents.
- Original connection UIDs support malicious-connection recall. They are not independently annotated attack episodes. Capture spans may include gaps; no false-incidents-per-benign-hour or end-to-end latency claim is made.

## Frozen prospective comparison

The candidate is predetermined: **RF seed 42, threshold selected for a 0.1% public-validation FPR budget**. It is compared against the original validation-F1 RF policy. This is a simple operating-point experiment, not a claim that threshold selection is novel.

`compare` writes `frozen_policy.json` with model hashes, thresholds, and code/protocol fingerprints before fresh captures are processed. Fresh outputs record that freeze's hash. Do not change the policy after seeing fresh results. Changing code, dependencies, seeds or smoke/full mode requires a new output directory. Results from the already published test captures are diagnostic/exploratory.

The pilot target is a 20% reduction in window false positives with at most two percentage points of recall loss on fresh data. Whether that target is met is distinct from whether there is an original paper contribution. Broader validation and closest-work comparison remain necessary.

## Outputs and recovery

Each experiment contains:

- `manifest.json`: source commit, per-file hashes, dependency versions, protocol, seeds and preservation hashes.
- `data/`: compressed features plus times, identifiers, labels/subtypes, label reasons and rule masks; no identifier is a learned feature.
- `predictions/`: compressed CSVs with all supported windows, scores and policy decisions.
- `baseline.json`, `comparisons.json`, `metrics.csv`: measured detector and classifier results.
- `feature_diagnostics.csv`: descriptive error associations; not causal explanations.
- `figures/`: PNG/PDF figures, and `results_table.tex` for later manuscript preparation.
- `FINDINGS.md`, `research_decision.json`: readable findings and the evidence gate.
- `last_status.json`: completion/failure status and preservation check.

Completed captures are cached with hashes, models are checkpointed, and completed comparisons can resume. Partial files do not count as completed captures. Rerun the same command after interruption. The CLI checks its deadline while reading packets and between steps/models; Kaggle's job limit and notebook subprocess timeout provide the outer four-hour bound.

Software tests validate scientific accounting; they do not validate model generalization. Per-capture outcomes and pooled outcomes must be interpreted together. Five seeds do not compensate for a small number of independent captures.

## Kaggle automation

```bash
# Keep credentials outside the checkout; use a private writable config folder.
export KAGGLE_CONFIG_DIR=/tmp/codealpha-kaggle
.venv/bin/python tools/kaggle_cli.py auth login --no-launch-browser
.venv/bin/python tools/prepare_kaggle.py --owner YOUR_KAGGLE_USERNAME --smoke --output artifacts/kaggle/smoke
.venv/bin/python tools/kaggle_cli.py kernels push -p artifacts/kaggle/smoke -t 14400

# Once the smoke notebook completes, build the five-seed study with the fresh check.
.venv/bin/python tools/prepare_kaggle.py --owner YOUR_KAGGLE_USERNAME --fresh --output artifacts/kaggle/pilot
.venv/bin/python tools/kaggle_cli.py kernels push -p artifacts/kaggle/pilot -t 14400
.venv/bin/python tools/kaggle_cli.py kernels status YOUR_KAGGLE_USERNAME/signalwatch-false-alarm-study
.venv/bin/python tools/kaggle_cli.py kernels logs YOUR_KAGGLE_USERNAME/signalwatch-false-alarm-study
.venv/bin/python tools/kaggle_cli.py kernels output YOUR_KAGGLE_USERNAME/signalwatch-false-alarm-study -p artifacts/kaggle/results --file-pattern 'signalwatch-evidence.*'
```

The wrapper uses the official SDK and CLI. It corrects Kaggle 2.2.5's login-command bootstrap and inconsistent OAuth storage defaults. A token may alternatively be stored in the private config folder's `access_token` file with mode 600. It is loaded into the child process without inclusion in generated source.

Generated notebooks are private and CPU-only. They contain a checksummed allowlisted source bundle, so they do not need GitHub credentials or a public branch. Python 3.12 is provisioned with pinned `uv` tooling because Kaggle images may use another Python release and omit `ensurepip`. Library installation, training and software tests use an isolated environment. Runtime caches stay in `/tmp`; only the selected evidence archive is exported. The notebook can also be run manually.

### Offline Kaggle inputs

When remote Internet access is unavailable, use Kaggle's supported private dataset attachments. The offline input builder packages the local Python 3.12 runtime, downloaded dependency wheels and allowlisted packet/label files. Third-party installed packages, credentials and environment dumps are excluded. Python's license and source notices are retained.

```bash
.venv/bin/python -m pip download -r requirements-research.txt -d artifacts/kaggle/wheels
.venv/bin/python tools/prepare_kaggle_inputs.py --owner YOUR_KAGGLE_USERNAME --raw artifacts/research/pilot/raw
.venv/bin/python tools/kaggle_cli.py datasets create -p artifacts/kaggle/inputs -q
.venv/bin/python tools/prepare_kaggle.py --owner YOUR_KAGGLE_USERNAME --fresh \
  --dataset YOUR_KAGGLE_USERNAME/signalwatch-offline-research-inputs \
  --input-manifest artifacts/kaggle/inputs/input_manifest.json --output artifacts/kaggle/pilot
```

The notebook pins the input-manifest hash, checks every attached archive, installs wheels with `--no-index`, and disables Internet in its metadata. Include fresh files in the private attachment only after freezing the local policy. Use `datasets version` for a subsequent input version, without deleting prior versions. The source manifest hash prevents a newer dataset version from silently changing a replayed experiment.

## Paper preparation

The `paper/` directory contains an IEEEtran manuscript scaffold and verified initial references. Insert results only after checking the run evidence and research limitations. Select a conference after determining the contribution. Current bibliography entries are a starting point; the closest-work assessment must cover recent calibration, workload, and aggregation studies before asserting novelty.

