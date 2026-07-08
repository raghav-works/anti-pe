"""JSON-friendly structures used by scanner support modules."""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from typing import Any


@dataclass(slots=True)
class PolicyConfig:
    scan_enabled: bool = True
    mode: str = "alert_only"
    alert_threshold: float = 0.6242529630641415
    block_threshold: float = 0.9385114343804422
    max_file_size_mb: int = 100
    quarantine_enabled: bool = False


@dataclass(slots=True)
class FileInfo:
    path: str | None = None
    name: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    is_pe: bool | None = None
    type: str | None = None


@dataclass(slots=True)
class ModelInfo:
    model_name: str | None = None
    model_version: str | None = None
    model_type: str = "lightgbm"
    feature_dim: int | None = None
    score: float | None = None


@dataclass(slots=True)
class DecisionInfo:
    verdict: str
    action: str
    score: float | None = None
    alert_threshold: float | None = None
    block_threshold: float | None = None
    mode: str | None = None


@dataclass(slots=True)
class ScanError:
    code: str
    message: str
    details: dict[str, Any] | None = None


@dataclass(slots=True)
class ScanResult:
    scan_status: str
    file: FileInfo | None = None
    model: ModelInfo | None = None
    decision: DecisionInfo | None = None
    error: ScanError | None = None


@dataclass(slots=True)
class ValidationResult:
    is_valid_pe: bool
    scan_status: str
    file_path: str
    file_name: str | None = None
    size_bytes: int | None = None
    error_message: str | None = None


def to_jsonable(value: Any) -> Any:
    """Convert dataclasses and common containers into JSON-friendly values."""
    if is_dataclass(value):
        return {key: to_jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    return value
