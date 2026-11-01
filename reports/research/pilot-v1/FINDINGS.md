# Signalwatch false-alarm study

Published-test results are diagnostic/exploratory. Fresh evaluation uses a separately frozen policy.

Source commit: `f36662b489ba135ca5ef150b5fdbc309d1c2096e`. Code fingerprint: `9921e9e3e020b480f226a0de5f0366834de9bb4e3aa3876fe75dc39ae72f4002`.

## Baseline

| Domain | Windows | Precision | Recall | F1 | False-positive rate |
|---|---:|---:|---:|---:|---:|
| public | 187,534 | 98.87% | 92.22% | 95.43% | 15.41% |
| lab | 677 | 100.00% | 99.73% | 99.87% | 0.00% |

Reproduction checks: all recorded confusion matrices match.

## Where baseline mistakes occur

| Capture | Benign windows | False positives | FPR | Suspicious windows | Recall |
|---|---:|---:|---:|---:|---:|
| malware-3 | 5,712 | 616 | 10.78% | 175,568 | 92.22% |
| malware-42 | 5,396 | 1,226 | 22.72% | 9 | 33.33% |
| somfy-01 | 849 | 1 | 0.12% | 0 | undefined |
| lab-600 | 50 | 0 | 0.00% | 56 | 100.00% |
| lab-601 | 51 | 0 | 0.00% | 54 | 100.00% |
| lab-602 | 53 | 0 | 0.00% | 53 | 98.11% |
| lab-603 | 49 | 0 | 0.00% | 79 | 100.00% |
| lab-604 | 52 | 0 | 0.00% | 75 | 100.00% |
| lab-605 | 50 | 0 | 0.00% | 55 | 100.00% |

Feature medians for mistaken and correctly rejected benign traffic are in `feature_diagnostics.csv`. Differences describe associations; they do not establish a causal explanation.

## Classifier comparisons (seed 42)

| Domain | Model | Validation policy | Recall | FPR | F1 |
|---|---|---|---:|---:|---:|
| public | random_forest | validation_f1 | 92.22% | 15.41% | 95.43% |
| public | random_forest | fpr_0.001 | 84.71% | 14.80% | 91.22% |
| public | random_forest | fpr_0.005 | 93.53% | 16.26% | 96.10% |
| public | random_forest | fpr_0.01 | 93.81% | 16.76% | 96.24% |
| lab | random_forest | validation_f1 | 99.73% | 0.00% | 99.87% |
| lab | random_forest | fpr_0.001 | 99.73% | 0.00% | 99.87% |
| lab | random_forest | fpr_0.005 | 100.00% | 0.00% | 100.00% |
| lab | random_forest | fpr_0.01 | 100.00% | 0.00% | 100.00% |
| public | logistic_regression | validation_f1 | 26.51% | 50.76% | 40.80% |
| public | logistic_regression | fpr_0.001 | 0.00% | 0.00% | 0.00% |
| public | logistic_regression | fpr_0.005 | 0.00% | 0.00% | 0.00% |
| public | logistic_regression | fpr_0.01 | 0.00% | 0.00% | 0.00% |
| lab | logistic_regression | validation_f1 | 99.19% | 0.00% | 99.60% |
| lab | logistic_regression | fpr_0.001 | 0.00% | 0.00% | 0.00% |
| lab | logistic_regression | fpr_0.005 | 0.00% | 0.00% | 0.00% |
| lab | logistic_regression | fpr_0.01 | 0.00% | 0.00% | 0.00% |
| public | decision_tree | validation_f1 | 94.29% | 34.41% | 95.90% |
| public | decision_tree | fpr_0.001 | 0.00% | 0.00% | 0.00% |
| public | decision_tree | fpr_0.005 | 0.00% | 0.00% | 0.00% |
| public | decision_tree | fpr_0.01 | 0.00% | 0.00% | 0.00% |
| lab | decision_tree | validation_f1 | 100.00% | 0.66% | 99.73% |
| lab | decision_tree | fpr_0.001 | 0.00% | 0.00% | 0.00% |
| lab | decision_tree | fpr_0.005 | 0.00% | 0.00% | 0.00% |
| lab | decision_tree | fpr_0.01 | 0.00% | 0.00% | 0.00% |
| public | hist_gradient_boosting | validation_f1 | 98.33% | 27.69% | 98.22% |
| public | hist_gradient_boosting | fpr_0.001 | 5.60% | 4.81% | 10.57% |
| public | hist_gradient_boosting | fpr_0.005 | 5.60% | 4.81% | 10.57% |
| public | hist_gradient_boosting | fpr_0.01 | 5.60% | 4.81% | 10.57% |
| lab | hist_gradient_boosting | validation_f1 | 100.00% | 0.33% | 99.87% |
| lab | hist_gradient_boosting | fpr_0.001 | 0.00% | 0.00% | 0.00% |
| lab | hist_gradient_boosting | fpr_0.005 | 0.00% | 0.00% | 0.00% |
| lab | hist_gradient_boosting | fpr_0.01 | 0.00% | 0.00% | 0.00% |

## Fresh-capture check

Reference FPR 9.72%; candidate FPR 6.68%.
Reference recall 95.63%; candidate recall 66.07%.
Pilot improvement target met: False. This is not a publication decision.

## Interpretation and next decision

- RF, rules, and their union are evaluated on the same supported windows. Only CUSTOM-002 and CUSTOM-004 enter primary intrusion metrics.
- Other rule findings and the application's full event union are preserved in prediction exports. They have different meanings from malicious-flow labels.
- Incident grouping can change item counts. Pure-benign incident counts require every observed window in that group to be labeled benign; mixed/unknown groups are reported separately.
- Connection recall uses published connection labels. It is not independently annotated attack-episode recall.
- Capture spans can include gaps. False incidents per benign monitoring hour and end-to-end latency are not established by these offline measurements.
- Seeds measure model variability; they do not create independent network environments. Few test captures do not support narrow confidence intervals or broad generalization claims.
- The pilot target is 20% fewer false positives with at most a two-percentage-point recall loss on fresh captures; it is a project criterion, not an IEEE requirement.
- A full paper additionally requires a distinct contribution, more independent evaluation data, appropriate comparisons, and a full-text related-work review.
