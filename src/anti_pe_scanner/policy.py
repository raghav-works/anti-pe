"""Policy loading, merging, and validation."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping

from anti_pe_scanner.schemas import PolicyConfig

VALID_MODES = {"log_only", "alert_only", "block_enabled"}
DEFAULT_POLICY = PolicyConfig()


def _coerce_policy(data: PolicyConfig | Mapping[str, Any]) -> PolicyConfig:
    if isinstance(data, PolicyConfig):
        return data
    return PolicyConfig(**dict(data))


def validate_policy(policy: PolicyConfig) -> PolicyConfig:
    if policy.mode not in VALID_MODES:
        raise ValueError(
            f"Invalid policy mode {policy.mode!r}. Expected one of: {sorted(VALID_MODES)}"
        )
    if not 0 <= policy.alert_threshold <= 1:
        raise ValueError("alert_threshold must be between 0 and 1")
    if not 0 <= policy.block_threshold <= 1:
        raise ValueError("block_threshold must be between 0 and 1")
    if policy.alert_threshold >= policy.block_threshold:
        raise ValueError("alert_threshold must be less than block_threshold")
    if policy.max_file_size_mb <= 0:
        raise ValueError("max_file_size_mb must be positive")
    return policy


def load_policy(path: str | None) -> PolicyConfig:
    if path is None:
        return validate_policy(PolicyConfig())

    with Path(path).open("r", encoding="utf-8") as policy_file:
        data = json.load(policy_file)
    return validate_policy(_coerce_policy(data))


def merge_policy(
    base: PolicyConfig | Mapping[str, Any] | None = None,
    model_thresholds: Mapping[str, Any] | None = None,
    override: PolicyConfig | Mapping[str, Any] | None = None,
) -> PolicyConfig:
    merged = asdict(_coerce_policy(base or DEFAULT_POLICY))

    # Model thresholds set runtime defaults, while user policy overrides win last.
    if model_thresholds:
        for key in ("alert_threshold", "block_threshold"):
            if key in model_thresholds and model_thresholds[key] is not None:
                merged[key] = model_thresholds[key]

    if override:
        override_data = asdict(override) if isinstance(override, PolicyConfig) else dict(override)
        for key, value in override_data.items():
            if value is not None:
                merged[key] = value

    return validate_policy(PolicyConfig(**merged))

