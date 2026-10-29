# Model card: custom-rf-v1

## Purpose and intended use

A binary Random Forest classifier for a local educational network IDS. It flags suspicious statistical patterns in five-second bidirectional flow windows. Custom rules independently detect defined protocol indicators. Human investigation follows an alert; the model does not block traffic.

## Data and partitions

Public data: selected IoT-23 captures, attributed to Sebastian Garcia, Agustin Parmisano, and Maria Jose Erquiaga (2020), DOI 10.5281/zenodo.4743746. The published Zenodo dataset record specifies CC-BY-4.0. Source URLs and content hashes are in `data/sources.json` and `data/sources.lock.json`. The dataset landing page also contains historical CC-BY-2.0 metadata and older capture READMEs contain a generic authorization notice; attribution and source notices are retained, and raw captures are not redistributed here.

- Train: malware captures 8-1 and 20-1; twelve generated lab sessions.
- Validation: malware capture 21-1 and Honeypot 4-1; five independent lab sessions.
- Test: malware captures 3-1 and 42-1, plus Honeypot 7-1/Somfy-01; six independent lab sessions.

Capture/session groups do not cross partitions. Repeated windows from a connection stay within its source capture. Label joins require exactly one published connection interval covering the window: 1 ms start tolerance and 1 second end tolerance accommodate capture precision and final teardown. Unknown, unmatched, and ambiguous cases are excluded and counted. No rule outputs are used as labels.

## Inputs, training, and threshold

Schema `flow5-v1`: 22 features for duration, directional packet and network-layer byte counts, packet lengths, inter-arrival times, rates, TCP flag fractions, protocol indicators, and same-window per-source connection/destination-port counts. Source identifiers, raw addresses/ports, timestamps, labels, payload strings, and rule decisions do not enter the model.

Window boundaries are `floor(packet_timestamp / 5)`. Direction follows the first observed packet. Rates divide by at least 1 ms; standard deviations use population moments. TCP/UDP and ICMP are supported; fragments and non-IP traffic are excluded. The same decoder and extractor run for public training, generated sessions, PCAP analysis, and live capture.

Training uses 200 trees, depth 10, at most 256 leaves, `balanced_subsample` class weights, random seed 42, and two worker threads. Threshold candidates are 0.05–0.95 in steps of 0.01; the selected validation-F1 threshold is **0.95**, with higher thresholds winning ties. Hyperparameters and threshold were frozen before test evaluation and were not changed after viewing results.

The published artifact uses scikit-learn 1.9.1 and is approximately 190 KB. Exact hash, versions, parameters, feature order, importances, threshold, and CPU latency are in `models/metadata.json`. Scores are uncalibrated fractions of forest evidence, not verified probabilities of maliciousness.

## Held-out results

| Partition | Benign / suspicious windows | Precision | Recall | F1 | PR-AUC (average precision) | False-positive rate |
| --- | --- | --- | --- | --- | --- | --- |
| Public subset | 11,957 / 175,577 | 98.87% | 92.22% | 95.43% | 98.02% | 15.41% |
| Generated lab test | 305 / 372 | 100.00% | 99.73% | 99.87% | 100.00% | 0.00% |

Public confusion matrix: **TN 10,114; FP 1,843; FN 13,664; TP 161,913**. Lab confusion matrix: **TN 305; FP 0; FN 1; TP 371**.

The public majority baseline predicts suspicious for every sample: F1 96.71%, recall 100%, and false-positive rate 100%. Its F1 exceeds the model's because the test set is overwhelmingly positive. Balanced accuracy is 88.40% for this model and 50% for the baseline. This model improves benign rejection but still creates substantial false alarms.

## Live demonstration and limitations

Live demonstrations are separate from held-out metrics. In the initial combined rule scenario, the frozen model did not flag any windows, including its fixed-size UDP burst. A separate variable-size burst exercises a supported model pattern and generated a live ML alert. That demonstration was not added to training or relabeled as held-out evaluation.

Generated lab traffic is simplified and much easier than the public subset. Capture groups reduce leakage but do not establish independence of windows or broad generalization. The public data is old, IoT-specific, highly imbalanced, and includes long correlated malicious connections. Label matching omits some windows; coverage statistics must accompany results. The selected subset is not an evaluation of the full IoT-23 dataset.

Do not claim production readiness, universal attack detection, or calibrated confidence. Payload-based threats in encrypted traffic are not decrypted. Drift, new protocols, low-rate attacks, and unmodeled benign behavior can cause misses or false positives. Re-evaluate on independently labeled deployment data before changing thresholds or model versions; keep a new untouched test partition for subsequent research.

## Artifact handling

Only load the included trusted `joblib` artifact or one you generated yourself. A matching SHA-256 does not make an untrusted pickle safe. The application verifies the hash, schema, feature order, class labels, and exact scikit-learn version. Missing or incompatible artifacts disable ML visibly while preserving rule detections. There is no online learning or model upload interface.
