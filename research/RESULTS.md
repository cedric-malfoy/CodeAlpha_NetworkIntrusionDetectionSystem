# First research pilot: measured outcome

**The proposed cutoff change failed the pilot success criterion.** We have a reproducible study and a clearer diagnosis, but have not established a new detection method suitable for a full research paper.

## What ran

- All six published public/lab confusion matrices were reproduced exactly.
- Four classifiers were evaluated with five seeds: 20 classifier/seed comparisons.
- Rules alone, machine learning alone, and their union were measured on common supported windows.
- A candidate cutoff was selected using validation data and frozen before opening two additional IoT-23 captures.
- The new captures yielded 1,074,392 labeled windows. Label coverage was 96.68% and 96.13% of extracted windows; unsupported packets remain a separate coverage limitation.
- The source model and published baseline files were preserved. A portable offline environment also completed the software smoke pipeline.

## Main result on the two additional captures

| Policy | Cutoff | Normal windows incorrectly flagged | Suspicious windows detected |
|---|---:|---:|---:|
| Original RF operating point | 0.95 | 9.72% | 95.63% |
| Validation-budget candidate | 0.97 | 6.68% | 66.07% |

The candidate reduced false positives from 46,285 to 31,843, about 31.2%. However, detection recall fell by 29.56 percentage points. The predeclared goal allowed at most a two-point loss, so this is **not a successful improvement**.

These percentages describe labeled five-second traffic windows. They are not percentages of independent attack campaigns. The pooled result is dominated by capture 1-1; the [full findings](../reports/research/pilot-v1/FINDINGS.md) include capture-specific outcomes and limits.

## What explains some of the mistakes

Every one of the 1,843 false-positive windows in the reproduced published public test was TCP traffic. Capture 42-1 contributed 1,226 of them.

Of the 1,843 false positives, 796 (43.19%) had exactly the same 22-feature values as at least one maliciously labeled training window. A deterministic classifier using only those features assigns the same score to identical vectors. It therefore cannot distinguish those paired examples just by moving its cutoff. This shows ambiguity relative to the published labels; it does not establish that the labels are perfect or explain all errors.

The reproducible descriptive audit is in [ERROR_ANALYSIS.md](../reports/research/pilot-v1/ERROR_ANALYSIS.md). It did not select or alter the frozen prospective policy.

## What is available

- [Findings and comparison tables](../reports/research/pilot-v1/FINDINGS.md)
- [Recorded code verification](../reports/research/pilot-v1/source_verification.json)
- [Frozen policy](../reports/research/pilot-v1/frozen_policy.json)
- [All comparison metrics](../reports/research/pilot-v1/metrics.csv)
- [Fresh-data coverage](../reports/research/pilot-v1/fresh_coverage.json)
- [Scientific figures](../reports/research/pilot-v1/figures/)
- [IEEE manuscript scaffold](../paper/README.md)

The core source hashes for the completed local experiment match commit `96977c4`. The original run manifest also records its earlier checkout commit and dirty working-tree state; source-content verification resolves that provenance without rewriting the original manifest. Later notebook-packaging edits do not change the completed detector experiments.

## Kaggle status

Authentication and private notebook submission worked. Remote execution has not completed successfully: external DNS failed in the online run, and Kaggle's dataset API denied access to the private offline input dataset after reporting creation. The account owner also confirmed that the dataset was missing or inaccessible. These are recorded external blockers, not successful remote benchmark results.

The offline input archive, notebook generation and local execution remain available. Resolve private dataset access in Kaggle before claiming that the cloud notebook has run. Credentials are not included in source, notebooks or evidence.

## Research decision

Do not submit the cutoff change as a novel successful method. The next useful investigation is whether independently validated temporal or connection context can resolve the observed feature ambiguity. That requires a new development protocol and another reserved evaluation set. The current fresh captures have now been inspected and cannot be repeatedly reused as an untouched test.

Before developing a full IEEE paper, establish a distinct contribution against the closest published work and broaden independent evaluation. The current artifact supports that next research step and can support a carefully scoped reproducibility discussion; publication readiness has not been demonstrated.
