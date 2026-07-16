"""Single-read, single-parse preparation for PE scanning."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter_ns
from typing import Any

from anti_pe_scanner.errors import (
    STATUS_FILE_NOT_FOUND,
    STATUS_PARSE_ERROR,
    STATUS_READ_ERROR,
    STATUS_SKIPPED_NOT_PE,
    STATUS_SKIPPED_TOO_LARGE,
)

DOS_HEADER_PE_OFFSET_FIELD = 0x3C
PE_SIGNATURE = b"PE\x00\x00"


@dataclass(slots=True)
class PreparedPEFile:
    path: Path
    name: str
    size_bytes: int
    raw_bytes: bytes
    sha256: str
    lief_binary: Any
    timings_ms: dict[str, float] = field(default_factory=dict)


class PEPreparationError(ValueError):
    """Structured preparation failure that maps to an existing scan status."""

    def __init__(
        self,
        scan_status: str,
        message: str,
        path: Path,
        size_bytes: int | None = None,
        sha256: str | None = None,
        timings_ms: dict[str, float] | None = None,
    ) -> None:
        super().__init__(message)
        self.scan_status = scan_status
        self.path = path
        self.size_bytes = size_bytes
        self.sha256 = sha256
        self.timings_ms = timings_ms or {}


def _elapsed_ms(start_ns: int) -> float:
    return (perf_counter_ns() - start_ns) / 1_000_000.0


def _validate_headers(raw_bytes: bytes, path: Path) -> None:
    if not raw_bytes:
        raise PEPreparationError(STATUS_SKIPPED_NOT_PE, "File is empty", path, 0)
    if raw_bytes[:2] != b"MZ":
        raise PEPreparationError(
            STATUS_SKIPPED_NOT_PE, "Missing MZ header", path, len(raw_bytes)
        )
    if len(raw_bytes) < DOS_HEADER_PE_OFFSET_FIELD + 4:
        raise PEPreparationError(
            STATUS_PARSE_ERROR, "Missing PE header offset", path, len(raw_bytes)
        )
    e_lfanew = struct.unpack_from("<I", raw_bytes, DOS_HEADER_PE_OFFSET_FIELD)[0]
    if e_lfanew <= 0 or e_lfanew > len(raw_bytes) - len(PE_SIGNATURE):
        raise PEPreparationError(
            STATUS_PARSE_ERROR, "Invalid PE header offset", path, len(raw_bytes)
        )
    if raw_bytes[e_lfanew : e_lfanew + 4] != PE_SIGNATURE:
        raise PEPreparationError(
            STATUS_SKIPPED_NOT_PE, "Missing PE signature", path, len(raw_bytes)
        )


def prepare_pe_file(
    file_path: str | Path,
    max_file_size_mb: int = 100,
) -> PreparedPEFile:
    """Read, hash, validate, and parse a stable file exactly once."""
    path = Path(file_path)
    timings: dict[str, float] = {}

    start = perf_counter_ns()
    try:
        before = path.stat()
    except FileNotFoundError as exc:
        raise PEPreparationError(STATUS_FILE_NOT_FOUND, "File not found", path) from exc
    except OSError as exc:
        raise PEPreparationError(STATUS_READ_ERROR, str(exc), path) from exc
    timings["file_stat_ms"] = _elapsed_ms(start)

    if not path.is_file():
        raise PEPreparationError(
            STATUS_READ_ERROR, "Path is not a file", path, timings_ms=timings
        )
    if before.st_size == 0:
        raise PEPreparationError(
            STATUS_SKIPPED_NOT_PE, "File is empty", path, 0, timings_ms=timings
        )

    max_size_bytes = max_file_size_mb * 1024 * 1024
    if before.st_size > max_size_bytes:
        raise PEPreparationError(
            STATUS_SKIPPED_TOO_LARGE,
            f"File exceeds max size of {max_file_size_mb} MB",
            path,
            before.st_size,
            timings_ms=timings,
        )

    start = perf_counter_ns()
    try:
        raw_bytes = path.read_bytes()
        after = path.stat()
    except FileNotFoundError as exc:
        raise PEPreparationError(STATUS_FILE_NOT_FOUND, "File not found", path) from exc
    except (PermissionError, OSError) as exc:
        raise PEPreparationError(
            STATUS_READ_ERROR, str(exc), path, before.st_size, timings_ms=timings
        ) from exc
    timings["file_read_ms"] = _elapsed_ms(start)

    stable_fields = ("st_size", "st_mtime_ns", "st_ino")
    if len(raw_bytes) != before.st_size or any(
        getattr(before, field) != getattr(after, field) for field in stable_fields
    ):
        raise PEPreparationError(
            STATUS_READ_ERROR,
            "File changed while it was being read",
            path,
            len(raw_bytes),
            timings_ms=timings,
        )

    start = perf_counter_ns()
    digest = hashlib.sha256(raw_bytes).hexdigest()
    timings["sha256_ms"] = _elapsed_ms(start)

    start = perf_counter_ns()
    try:
        _validate_headers(raw_bytes, path)
    except PEPreparationError as exc:
        exc.sha256 = digest
        exc.timings_ms = {**timings, "header_validation_ms": _elapsed_ms(start)}
        raise
    timings["header_validation_ms"] = _elapsed_ms(start)

    try:
        import lief  # type: ignore

        try:
            lief.logging.disable()
        except Exception:
            pass
    except ImportError as exc:
        raise PEPreparationError(
            STATUS_PARSE_ERROR,
            "LIEF is required for PE feature extraction. Install dependency 'lief'.",
            path,
            len(raw_bytes),
            digest,
            timings,
        ) from exc

    start = perf_counter_ns()
    try:
        lief_binary = lief.PE.parse(raw_bytes)
    except Exception as exc:
        raise PEPreparationError(
            STATUS_PARSE_ERROR,
            f"LIEF parse failed after PE header validation: {exc}",
            path,
            len(raw_bytes),
            digest,
            {**timings, "lief_parse_ms": _elapsed_ms(start)},
        ) from exc
    timings["lief_parse_ms"] = _elapsed_ms(start)
    if lief_binary is None:
        raise PEPreparationError(
            STATUS_PARSE_ERROR,
            "LIEF parse failed after PE header validation: LIEF returned no PE object",
            path,
            len(raw_bytes),
            digest,
            timings,
        )

    return PreparedPEFile(
        path=path,
        name=path.name,
        size_bytes=len(raw_bytes),
        raw_bytes=raw_bytes,
        sha256=digest,
        lief_binary=lief_binary,
        timings_ms=timings,
    )
