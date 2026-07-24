"""Single-read/single-parse bridge to official EMBER v2 features."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np

from anti_pe_scanner.ember_v2_features import (
    EMBER_V2_DIM,
    FeatureExtractionError,
    PEFeatureExtractorV2,
)
from anti_pe_scanner.prepared_pe import PreparedPEFile, prepare_pe_file

EMBER_FEATURE_DIM = EMBER_V2_DIM


def extract_pe_features(file_path: str | Path) -> np.ndarray:
    return PEFeatureExtractor().extract_from_file(file_path)


def _validate_feature_vector(features: Any) -> np.ndarray:
    vector = np.asarray(features)
    if vector.shape == (1, EMBER_FEATURE_DIM):
        vector = vector[0]
    if vector.shape != (EMBER_FEATURE_DIM,):
        raise FeatureExtractionError(
            f"Feature vector must have shape ({EMBER_FEATURE_DIM},); got {vector.shape}"
        )
    if vector.dtype != np.float32:
        raise FeatureExtractionError(
            f"Feature vector must have dtype float32; got {vector.dtype}"
        )
    if not np.isfinite(vector).all():
        raise FeatureExtractionError("Feature vector contains NaN or infinite values")
    return vector.reshape(1, EMBER_FEATURE_DIM)


class PEFeatureExtractor:
    def __init__(self) -> None:
        self.ember = PEFeatureExtractorV2()

    def extract_from_file(self, file_path: str | Path) -> np.ndarray:
        try:
            return self.extract_prepared(prepare_pe_file(file_path))
        except FileNotFoundError:
            raise
        except FeatureExtractionError:
            raise
        except Exception as exc:
            if getattr(exc, "scan_status", None) == "file_not_found":
                raise FileNotFoundError(f"File not found: {file_path}") from exc
            raise FeatureExtractionError(str(exc)) from exc

    def extract_from_bytes(self, raw_bytes: bytes, source_name: str = "<bytes>") -> np.ndarray:
        if not raw_bytes:
            raise FeatureExtractionError(
                f"Cannot extract features from empty file: {source_name}"
            )
        try:
            import lief
            binary = lief.PE.parse(raw_bytes)
        except Exception as exc:
            raise FeatureExtractionError(
                f"LIEF failed to parse PE file {source_name}: {exc}"
            ) from exc
        if binary is None:
            raise FeatureExtractionError(f"LIEF failed to parse PE file {source_name}")
        return _validate_feature_vector(self.ember.feature_vector(raw_bytes, binary))

    def extract_prepared(
        self, prepared: PreparedPEFile, timings_ms: dict[str, float] | None = None
    ) -> np.ndarray:
        return _validate_feature_vector(
            self.ember.feature_vector(
                prepared.raw_bytes, prepared.lief_binary, timings_ms=timings_ms
            )
        )
