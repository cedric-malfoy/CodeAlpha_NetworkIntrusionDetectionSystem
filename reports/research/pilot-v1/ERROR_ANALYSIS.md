# Baseline false-alarm diagnosis

The reproduced public test contains **1,843 false-positive windows**. Of these, **796** have feature vectors identical to at least one maliciously labeled training window.

| Capture | False positives | Exact matches to malicious training vectors |
|---|---:|---:|
| malware-3 | 616 | 162 |
| malware-42 | 1,226 | 634 |
| somfy-01 | 1 | 0 |

Protocol counts and exact matching details are in `error_analysis.json`.

This is evidence of ambiguity in the current representation relative to the published labels. A deterministic classifier using only these features assigns identical scores to identical vectors. Changing its cutoff can trade false positives against missed positives, but cannot distinguish the paired vectors. This does not prove that all false alarms have this cause, that the source labels are perfect, or that the result generalizes beyond these captures.

The next research question is whether independently validated context or a better evaluation unit can resolve this ambiguity. That requires new development data and another reserved evaluation set; the already inspected fresh results must not become a repeatedly tuned test.
