"""Validate file paths before PE feature extraction.

The scanner receives a file path, but the ML model receives a 2381-dimensional
feature vector. This gate prevents random, empty, oversized, or malformed
non-PE files from reaching feature extraction or model scoring.
"""

from __future__ import annotations

import struct
from pathlib import Path

from anti_pe_scanner.errors import (
    STATUS_FILE_NOT_FOUND,
    STATUS_PARSE_ERROR,
    STATUS_READ_ERROR,
    STATUS_SKIPPED_NOT_PE,
    STATUS_SKIPPED_TOO_LARGE,
    STATUS_SUCCESS,
)
from anti_pe_scanner.schemas import ValidationResult

DOS_HEADER_PE_OFFSET_FIELD = 0x3C
PE_SIGNATURE = b"PE\x00\x00"


def validate_pe_file(file_path: str | Path, max_file_size_mb: int = 100) -> ValidationResult:
    path = Path(file_path)

    if not path.exists():
        return _result(False, STATUS_FILE_NOT_FOUND, path, error_message="File not found")

    if not path.is_file():
        return _result(False, STATUS_READ_ERROR, path, error_message="Path is not a file")

    try:
        size_bytes = path.stat().st_size
    except OSError as exc:
        return _result(False, STATUS_READ_ERROR, path, error_message=str(exc))

    if size_bytes == 0:
        return _result(
            False,
            STATUS_SKIPPED_NOT_PE,
            path,
            size_bytes=size_bytes,
            error_message="File is empty",
        )

    max_size_bytes = max_file_size_mb * 1024 * 1024
    if size_bytes > max_size_bytes:
        return _result(
            False,
            STATUS_SKIPPED_TOO_LARGE,
            path,
            size_bytes=size_bytes,
            error_message=f"File exceeds max size of {max_file_size_mb} MB",
        )

    try:
        with path.open("rb") as file_obj:
            mz_header = file_obj.read(2)
            if mz_header != b"MZ":
                return _result(
                    False,
                    STATUS_SKIPPED_NOT_PE,
                    path,
                    size_bytes=size_bytes,
                    error_message="Missing MZ header",
                )

            file_obj.seek(DOS_HEADER_PE_OFFSET_FIELD)
            e_lfanew_bytes = file_obj.read(4)
            if len(e_lfanew_bytes) != 4:
                return _result(
                    False,
                    STATUS_PARSE_ERROR,
                    path,
                    size_bytes=size_bytes,
                    error_message="Missing PE header offset",
                )

            e_lfanew = struct.unpack("<I", e_lfanew_bytes)[0]
            if e_lfanew <= 0 or e_lfanew > size_bytes - len(PE_SIGNATURE):
                return _result(
                    False,
                    STATUS_PARSE_ERROR,
                    path,
                    size_bytes=size_bytes,
                    error_message="Invalid PE header offset",
                )

            file_obj.seek(e_lfanew)
            pe_signature = file_obj.read(len(PE_SIGNATURE))
            if pe_signature != PE_SIGNATURE:
                return _result(
                    False,
                    STATUS_SKIPPED_NOT_PE,
                    path,
                    size_bytes=size_bytes,
                    error_message="Missing PE signature",
                )
    except PermissionError as exc:
        return _result(False, STATUS_READ_ERROR, path, size_bytes=size_bytes, error_message=str(exc))
    except OSError as exc:
        return _result(False, STATUS_READ_ERROR, path, size_bytes=size_bytes, error_message=str(exc))

    lief_error = _optional_lief_parse_error(path)
    if lief_error is not None:
        return _result(
            False,
            STATUS_PARSE_ERROR,
            path,
            size_bytes=size_bytes,
            error_message=f"LIEF parse failed after PE header validation: {lief_error}",
        )

    return _result(True, STATUS_SUCCESS, path, size_bytes=size_bytes)


def _optional_lief_parse_error(path: Path) -> str | None:
    try:
        import lief
    except ImportError:
        return None

    try:
        parsed = lief.PE.parse(str(path))
    except Exception as exc:  # pragma: no cover - depends on optional LIEF internals.
        return str(exc)

    if parsed is None:
        return "LIEF returned no PE object"
    return None


def _result(
    is_valid_pe: bool,
    scan_status: str,
    path: Path,
    size_bytes: int | None = None,
    error_message: str | None = None,
) -> ValidationResult:
    return ValidationResult(
        is_valid_pe=is_valid_pe,
        scan_status=scan_status,
        file_path=str(path),
        file_name=path.name,
        size_bytes=size_bytes,
        error_message=error_message,
    )
