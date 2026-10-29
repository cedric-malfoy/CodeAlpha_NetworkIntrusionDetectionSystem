# Training and evaluation notebook

Open [01_training_evaluation.ipynb](01_training_evaluation.ipynb) for an interactive reproduction of the custom IDS model workflow. The original published model was trained with Python scripts; this notebook makes those stages visible cell by cell using the same packet, feature, label, and metric code.

## Launch

From the repository root, use Python 3.12 and the optional pinned notebook environment:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-notebook.txt
python -m jupyterlab
```

If the virtual environment already exists, activate it rather than recreating it. In JupyterLab, open `notebooks/01_training_evaluation.ipynb` and select the Python kernel belonging to `.venv`. If it is not listed, register it from the activated environment:

```bash
python -m ipykernel install --user --name signalwatch \
  --display-name "Signalwatch (Python 3.12)"
```

Then select **Signalwatch (Python 3.12)**. Choose **Restart Kernel and Run All Cells** to reproduce the full workflow. The notebook finds the project root whether its working directory is the repository or `notebooks/`.

## What the cells do

1. Check versions, paths, artifact hashes, source manifests, and frozen partitions.
2. Reuse compatible prepared data or obtain the selected public data and prepare separate notebook caches with the shared extraction pipeline.
3. Inspect class balance, label coverage, and the 22-feature contract.
4. Fit a fresh Random Forest on training groups only.
5. Select the threshold using validation F1, then evaluate public and lab partitions separately.
6. Plot confusion matrices and precision-recall curves, and compare the majority baseline.
7. Save the experimental model, matching metadata, metrics, and figures; verify model loading and offline replay.
8. Run the Python software tests and confirm the published model/reports remain unchanged.

First-time data preparation needs Internet access for roughly 100 MB of public captures and labels and can take several minutes on a CPU. Subsequent runs can reuse compatible caches. When changing packet decoding, features, labels, or split assignments, invalidate the affected cache and prepare again; do not reuse arrays from a different feature contract.

## Outputs and limits

Notebook outputs go to the ignored directory `artifacts/notebook-runs/reproduction-v1/`, including plots, metrics, experimental model/metadata, and offline replay evidence. Reusing that output directory can replace previous experimental files; preserve it or choose another run directory when comparing experiments. The notebook does not automatically deploy a model or replace `models/detector.joblib`, `models/metadata.json`, or the published reports.

The test partitions and their results have already been published. Running this notebook reproduces that benchmark; it is not a new blind evaluation. Keep public/lab results separate, read false positives alongside F1, and use a new untouched holdout after tuning based on existing test results. Scores are uncalibrated model outputs, not attack probabilities. See [MODEL_CARD.md](../MODEL_CARD.md) for the recorded limitations.
