"""Single-file PE malware scanner orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from anti_pe_scanner.errors import (
    STATUS_FEATURE_ERROR,
    STATUS_MODEL_ERROR,
    STATUS_POLICY_DISABLED,
    STATUS_READ_ERROR,
    STATUS_SUCCESS,
)
from anti_pe_scanner.event_builder import build_event
from anti_pe_scanner.feature_extractor import FeatureExtractionError, extract_pe_features
from anti_pe_scanner.model_loader import LightGBMModelPackage
from anti_pe_scanner.pe_validator import validate_pe_file
from anti_pe_scanner.policy import load_policy, merge_policy
from anti_pe_scanner.schemas import FileInfo, ModelInfo, PolicyConfig, ScanError
from anti_pe_scanner.utils import file_size_bytes, sha256_file
from anti_pe_scanner.verdict import decide_verdict


class PEMalwareScanner:
    """Inference-only scanner for a single file path.

    The scanner receives a file path, validates that it is a Windows PE, turns
    it into the 2381-feature model input, then applies the already-trained
    LightGBM model. Training is intentionally outside this runtime.
    """

    def __init__(
        self,
        model_package_path: str | Path,
        policy_path: str | Path | None = None,
    ):
        self.model_package = LightGBMModelPackage(model_package_path)
        self.model_package.load()
        self.base_policy = load_policy(str(policy_path)) if policy_path is not None else load_policy(None)

    def scan_file(
        self,
        file_path: str | Path,
        policy: dict[str, Any] | PolicyConfig | None = None,
        host_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        path = Path(file_path)
        active_policy = merge_policy(
            base=self.base_policy,
            model_thresholds=self.model_package.thresholds,
            override=policy,
        )
        file_info = self._file_info(path, active_policy.max_file_size_mb)
        model_info = self._model_info()

        if not active_policy.scan_enabled:
            return build_event(
                scan_status=STATUS_POLICY_DISABLED,
                file_info=file_info,
                model_info=model_info,
                error=None,
                host_context=host_context,
            )

        validation = validate_pe_file(path, active_policy.max_file_size_mb)
        file_info = self._file_info_from_validation(validation, active_policy.max_file_size_mb)
        if not validation.is_valid_pe:
            return build_event(
                scan_status=validation.scan_status,
                file_info=file_info,
                model_info=model_info,
                error=ScanError(
                    code=validation.scan_status,
                    message=validation.error_message or "PE validation failed",
                ),
                host_context=host_context,
            )

        try:
            features = extract_pe_features(path)
        except (FeatureExtractionError, FileNotFoundError, ValueError, OSError) as exc:
            return build_event(
                scan_status=STATUS_FEATURE_ERROR,
                file_info=file_info,
                model_info=model_info,
                error=ScanError(code=STATUS_FEATURE_ERROR, message=str(exc)),
                host_context=host_context,
            )

        try:
            score = self.model_package.predict_score(features)
        except Exception as exc:
            return build_event(
                scan_status=STATUS_MODEL_ERROR,
                file_info=file_info,
                model_info=model_info,
                error=ScanError(code=STATUS_MODEL_ERROR, message=str(exc)),
                host_context=host_context,
            )

        model_info.score = score
        decision = decide_verdict(score, active_policy)
        return build_event(
            scan_status=STATUS_SUCCESS,
            file_info=file_info,
            model_info=model_info,
            decision_info=decision,
            error=None,
            host_context=host_context,
        )

    def _model_info(self) -> ModelInfo:
        metadata = self.model_package.metadata or {}
        return ModelInfo(
            model_name=metadata.get("model_name"),
            model_version=metadata.get("model_version"),
            model_type=metadata.get("model_type", "lightgbm"),
            feature_dim=metadata.get("feature_dim"),
        )

    def _file_info_from_validation(self, validation, max_file_size_mb: int) -> FileInfo:
        info = self._file_info(Path(validation.file_path), max_file_size_mb)
        info.name = validation.file_name
        info.size_bytes = validation.size_bytes
        info.is_pe = validation.is_valid_pe
        info.type = "windows_pe" if validation.is_valid_pe else "non_pe"
        return info

    @staticmethod
    def _file_info(path: Path, max_file_size_mb: int) -> FileInfo:
        info = FileInfo(path=str(path), name=path.name, type="unknown")
        try:
            if path.is_file():
                info.size_bytes = file_size_bytes(path)
                max_hash_size = max_file_size_mb * 1024 * 1024
                if info.size_bytes <= max_hash_size:
                    info.sha256 = sha256_file(path)
        except OSError:
            info.type = STATUS_READ_ERROR
        return info
