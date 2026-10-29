"""Load only the repository's trusted artifact after hash/schema/version checks."""
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import sklearn

from .features import FEATURES, SCHEMA


class Model:
    def __init__(self, directory=None):
        self.estimator = None
        self.metadata = {}
        self.status = "unavailable"
        self.error = ""
        directory = Path(directory) if directory else Path(__file__).resolve().parents[1] / "models"
        try:
            metadata = json.loads((directory / "metadata.json").read_text())
            if metadata["schema"] != SCHEMA or metadata["features"] != list(FEATURES):
                raise ValueError("Feature schema is incompatible")
            if metadata["sklearn_version"] != sklearn.__version__:
                raise ValueError("scikit-learn version is incompatible; install pinned dependencies")
            artifact = directory / "detector.joblib"
            if hashlib.sha256(artifact.read_bytes()).hexdigest() != metadata["sha256"]:
                raise ValueError("Model hash mismatch")
            if not 0 <= metadata["threshold"] <= 1:
                raise ValueError("Invalid model threshold")
            # joblib is pickle-based. This is not an upload endpoint and a hash is
            # an integrity check, not a sandbox: load only trusted project artifacts.
            self.estimator = joblib.load(artifact)
            if self.estimator.n_features_in_ != len(FEATURES) or list(self.estimator.classes_) != [0, 1]:
                raise ValueError("Model dimensions/classes are incompatible")
            self.metadata, self.status = metadata, "ready"
        except (OSError, ValueError, KeyError, TypeError, EOFError) as error:
            self.estimator = None
            self.error = str(error)

    def scores(self, windows):
        if self.estimator is None:
            return [None] * len(windows)
        values = np.asarray([window["values"] for window in windows], dtype=float)
        if values.shape != (len(windows), len(FEATURES)) or not np.isfinite(values).all():
            raise ValueError("Invalid feature matrix")
        return self.estimator.predict_proba(values)[:, 1].tolist()
