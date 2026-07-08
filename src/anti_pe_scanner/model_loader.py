"""Inference-only LightGBM model package loader.

The bundled `model.txt` is an already-trained LightGBM Booster. This module
only loads that artifact and runs inference; training is intentionally not done
here. The model package is expected to use the 2381-feature EMBER-style PE
feature vector captured in `feature_config.json`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np

from anti_pe_scanner.policy import validate_policy
from anti_pe_scanner.schemas import PolicyConfig

EXPECTED_FEATURE_DIM = 2381


class LightGBMModelPackage:
    def __init__(self, model_package_path: str | Path):
        self.model_package_path = Path(model_package_path)
        self.model = None
        self.metadata: dict[str, Any] | None = None
        self.thresholds: dict[str, Any] | None = None
        self.feature_config: dict[str, Any] | None = None

    def load(self) -> None:
        model_path = self.model_package_path / "model.txt"
        metadata_path = self.model_package_path / "metadata.json"
        thresholds_path = self.model_package_path / "thresholds.json"
        feature_config_path = self.model_package_path / "feature_config.json"

        self._require_file(model_path)
        self._require_file(metadata_path)
        self._require_file(thresholds_path)
        self._require_file(feature_config_path)

        self.metadata = self._load_json(metadata_path)
        self.thresholds = self._load_json(thresholds_path)
        self.feature_config = self._load_json(feature_config_path)
        self._validate_package_metadata()

        # The model is already trained; LightGBM only deserializes it here.
        import lightgbm

        self.model = lightgbm.Booster(model_file=str(model_path))

    def predict_score(self, features) -> float:
        if self.model is None:
            raise RuntimeError("Model package is not loaded. Call load() before predict_score().")

        feature_array = self._coerce_features(features)
        prediction = self.model.predict(feature_array)
        return float(np.asarray(prediction).reshape(-1)[0])

    @staticmethod
    def _require_file(path: Path) -> None:
        if not path.is_file():
            raise FileNotFoundError(f"Required model package file not found: {path}")

    @staticmethod
    def _load_json(path: Path) -> dict[str, Any]:
        with path.open("r", encoding="utf-8") as file_obj:
            return json.load(file_obj)

    def _validate_package_metadata(self) -> None:
        if self.metadata is None or self.thresholds is None or self.feature_config is None:
            raise RuntimeError("Model package metadata has not been loaded")

        model_type = self.metadata.get("model_type")
        if model_type != "lightgbm":
            raise ValueError(f"metadata.json model_type must be 'lightgbm', got {model_type!r}")

        metadata_feature_dim = self.metadata.get("feature_dim")
        feature_config_dim = self.feature_config.get("feature_dim")
        if metadata_feature_dim != EXPECTED_FEATURE_DIM:
            raise ValueError(
                f"metadata.json feature_dim must be {EXPECTED_FEATURE_DIM}, "
                f"got {metadata_feature_dim!r}"
            )
        if feature_config_dim != EXPECTED_FEATURE_DIM:
            raise ValueError(
                f"feature_config.json feature_dim must be {EXPECTED_FEATURE_DIM}, "
                f"got {feature_config_dim!r}"
            )

        validate_policy(
            PolicyConfig(
                alert_threshold=float(self.thresholds.get("alert_threshold")),
                block_threshold=float(self.thresholds.get("block_threshold")),
            )
        )

    @staticmethod
    def _coerce_features(features) -> np.ndarray:
        feature_array = np.asarray(features, dtype=np.float32)

        # The trained Booster expects exactly one 2381-dimensional feature row.
        if feature_array.shape == (EXPECTED_FEATURE_DIM,):
            return feature_array.reshape(1, EXPECTED_FEATURE_DIM)
        if feature_array.shape == (1, EXPECTED_FEATURE_DIM):
            return feature_array

        raise ValueError(
            "features must have shape "
            f"({EXPECTED_FEATURE_DIM},) or (1, {EXPECTED_FEATURE_DIM}); "
            f"got {feature_array.shape}"
        )
