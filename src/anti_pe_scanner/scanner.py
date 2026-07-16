"""Single-file PE malware scanner orchestration."""

from __future__ import annotations

import copy
from collections import OrderedDict
from pathlib import Path
from time import perf_counter_ns
from typing import Any

from anti_pe_scanner.errors import (
    STATUS_FEATURE_ERROR,
    STATUS_MODEL_ERROR,
    STATUS_POLICY_DISABLED,
    STATUS_READ_ERROR,
    STATUS_SUCCESS,
)
from anti_pe_scanner.event_builder import build_event
from anti_pe_scanner.feature_extractor import FeatureExtractionError, PEFeatureExtractor
from anti_pe_scanner.model_loader import LightGBMModelPackage
from anti_pe_scanner.policy import load_policy, merge_policy
from anti_pe_scanner.prepared_pe import PEPreparationError, prepare_pe_file
from anti_pe_scanner.schemas import FileInfo, ModelInfo, PolicyConfig, ScanError
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
        cache_size: int = 0,
        num_threads: int | None = 1,
    ):
        start = perf_counter_ns()
        self.model_package = LightGBMModelPackage(model_package_path, num_threads=num_threads)
        self.model_package.load()
        self.model_load_ms = (perf_counter_ns() - start) / 1_000_000.0
        start = perf_counter_ns()
        self.base_policy = load_policy(str(policy_path)) if policy_path is not None else load_policy(None)
        self.policy_load_ms = (perf_counter_ns() - start) / 1_000_000.0
        self.feature_extractor = PEFeatureExtractor()
        self.cache_size = max(int(cache_size), 0)
        self._cache: OrderedDict[tuple[Any, ...], dict[str, Any]] = OrderedDict()
        self.cache_hits = 0

    def scan_file(
        self,
        file_path: str | Path,
        policy: dict[str, Any] | PolicyConfig | None = None,
        host_context: dict[str, Any] | None = None,
        *,
        include_telemetry: bool = False,
        trusted_sha256: str | None = None,
    ) -> dict[str, Any]:
        event, timings = self.scan_file_with_timings(
            file_path,
            policy=policy,
            host_context=host_context,
            trusted_sha256=trusted_sha256,
        )
        if include_telemetry:
            event["telemetry"] = {"latency_ms": timings}
        return event

    def scan_file_with_timings(
        self,
        file_path: str | Path,
        policy: dict[str, Any] | PolicyConfig | None = None,
        host_context: dict[str, Any] | None = None,
        *,
        trusted_sha256: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, float | bool]]:
        total_start = perf_counter_ns()
        timings: dict[str, float | bool] = {
            "model_load_ms": self.model_load_ms,
            "policy_load_ms": self.policy_load_ms,
            "cache_hit": False,
        }
        path = Path(file_path)
        start = perf_counter_ns()
        active_policy = merge_policy(
            base=self.base_policy,
            model_thresholds=self.model_package.thresholds,
            override=policy,
        )
        timings["verdict_policy_merge_ms"] = (perf_counter_ns() - start) / 1_000_000.0
        file_info = FileInfo(path=str(path), name=path.name, type="unknown")
        model_info = self._model_info()

        if not active_policy.scan_enabled:
            event = build_event(
                scan_status=STATUS_POLICY_DISABLED,
                file_info=file_info,
                model_info=model_info,
                error=None,
                host_context=host_context,
            )
            timings["total_scan_ms"] = (perf_counter_ns() - total_start) / 1_000_000.0
            return event, timings

        try:
            prepared = prepare_pe_file(path, active_policy.max_file_size_mb)
            timings.update(prepared.timings_ms)
        except PEPreparationError as exc:
            timings.update(exc.timings_ms)
            file_info.size_bytes = exc.size_bytes
            file_info.sha256 = exc.sha256
            file_info.is_pe = False
            file_info.type = "non_pe"
            event = build_event(
                scan_status=exc.scan_status,
                file_info=file_info,
                model_info=model_info,
                error=ScanError(
                    code=exc.scan_status,
                    message=str(exc),
                ),
                host_context=host_context,
            )
            timings["total_scan_ms"] = (perf_counter_ns() - total_start) / 1_000_000.0
            return event, timings

        file_info = FileInfo(
            path=str(path),
            name=prepared.name,
            size_bytes=prepared.size_bytes,
            sha256=prepared.sha256,
            is_pe=True,
            type="windows_pe",
        )
        if trusted_sha256 is not None and trusted_sha256.lower() != prepared.sha256:
            event = build_event(
                scan_status=STATUS_READ_ERROR,
                file_info=file_info,
                model_info=model_info,
                error=ScanError(
                    code=STATUS_READ_ERROR,
                    message="Agent-provided SHA-256 does not match the scanned content",
                ),
                host_context=host_context,
            )
            timings["total_scan_ms"] = (perf_counter_ns() - total_start) / 1_000_000.0
            return event, timings

        cache_key = self._cache_key(prepared.sha256, active_policy)
        cached = self._cache.get(cache_key)
        if cached is not None:
            self._cache.move_to_end(cache_key)
            self.cache_hits += 1
            timings["cache_hit"] = True
            event = copy.deepcopy(cached)
            event["timestamp"] = build_event(STATUS_SUCCESS)["timestamp"]
            if host_context is not None:
                event["host_context"] = copy.deepcopy(host_context)
            else:
                event.pop("host_context", None)
            timings["total_scan_ms"] = (perf_counter_ns() - total_start) / 1_000_000.0
            return event, timings

        try:
            start = perf_counter_ns()
            feature_timings: dict[str, float] = {}
            features = self.feature_extractor.extract_prepared(prepared, feature_timings)
            timings.update(feature_timings)
            timings["complete_feature_extraction_ms"] = (
                perf_counter_ns() - start
            ) / 1_000_000.0
        except (FeatureExtractionError, FileNotFoundError, ValueError, OSError) as exc:
            event = build_event(
                scan_status=STATUS_FEATURE_ERROR,
                file_info=file_info,
                model_info=model_info,
                error=ScanError(code=STATUS_FEATURE_ERROR, message=str(exc)),
                host_context=host_context,
            )
            timings["total_scan_ms"] = (perf_counter_ns() - total_start) / 1_000_000.0
            return event, timings

        try:
            start = perf_counter_ns()
            score = self.model_package.predict_score(features)
            timings["model_inference_ms"] = (perf_counter_ns() - start) / 1_000_000.0
        except Exception as exc:
            event = build_event(
                scan_status=STATUS_MODEL_ERROR,
                file_info=file_info,
                model_info=model_info,
                error=ScanError(code=STATUS_MODEL_ERROR, message=str(exc)),
                host_context=host_context,
            )
            timings["total_scan_ms"] = (perf_counter_ns() - total_start) / 1_000_000.0
            return event, timings

        model_info.score = score
        start = perf_counter_ns()
        decision = decide_verdict(score, active_policy)
        timings["verdict_ms"] = (perf_counter_ns() - start) / 1_000_000.0
        event = build_event(
            scan_status=STATUS_SUCCESS,
            file_info=file_info,
            model_info=model_info,
            decision_info=decision,
            error=None,
            host_context=host_context,
        )
        if self.cache_size:
            self._cache[cache_key] = copy.deepcopy(event)
            self._cache.move_to_end(cache_key)
            while len(self._cache) > self.cache_size:
                self._cache.popitem(last=False)
        timings["total_scan_ms"] = (perf_counter_ns() - total_start) / 1_000_000.0
        return event, timings

    def _model_info(self) -> ModelInfo:
        metadata = self.model_package.metadata or {}
        return ModelInfo(
            model_name=metadata.get("model_name"),
            model_version=metadata.get("model_version"),
            model_type=metadata.get("model_type", "lightgbm"),
            feature_dim=metadata.get("feature_dim"),
        )

    def _cache_key(self, sha256: str, policy: PolicyConfig) -> tuple[Any, ...]:
        metadata = self.model_package.metadata or {}
        return (
            sha256,
            metadata.get("model_version"),
            metadata.get("feature_version"),
            policy.scan_enabled,
            policy.mode,
            policy.alert_threshold,
            policy.block_threshold,
            policy.max_file_size_mb,
        )
