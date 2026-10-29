# Sources and attribution

- Garcia, S., Parmisano, A., and Erquiaga, M. J. (2020). **IoT-23: A labeled dataset with malicious and benign IoT network traffic**, version 1.0.0. [Dataset landing page](https://www.stratosphereips.org/datasets-iot23); [Zenodo DOI and license record](https://doi.org/10.5281/zenodo.4743746). The Zenodo record specifies CC-BY-4.0. Historical page metadata lists CC-BY-2.0 and older generic capture notices are documented in the model card. Only a selected subset is analyzed; raw captures and logs are not redistributed in this repository.
- [Scapy documentation](https://scapy.readthedocs.io/en/latest/): packet decoding, capture, and PCAP handling. It is a library used by our pipeline, not an external detection engine.
- [scikit-learn RandomForestClassifier](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html): classifier implementation and parameter meanings.
- [scikit-learn model evaluation](https://scikit-learn.org/stable/modules/model_evaluation.html): classification metrics, average precision, and confusion matrices.
- [scikit-learn common pitfalls](https://scikit-learn.org/stable/common_pitfalls.html): leakage prevention and consistent preprocessing.
- [scikit-learn model persistence](https://scikit-learn.org/stable/model_persistence.html): version compatibility and pickle-based artifact trust.
- [Flask documentation](https://flask.palletsprojects.com/en/stable/): local read-only API and browser dashboard.
- [Docker Compose networking](https://docs.docker.com/compose/how-tos/networking/): shared service network namespaces and isolated lab networking.

All rules, feature extraction, labeling joins, incident logic, dashboard code, reports, and synthetic scenarios were written for this project. Reserved `.example` domains and documentation-only IP ranges identify invented examples. Live Docker addresses are assigned to this project's internal network. The rule domain is not a real threat-intelligence feed.
