"""Small filesystem and JSON helpers."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from anti_pe_scanner.schemas import to_jsonable


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_json_dumps(data: Any, pretty: bool = False) -> str:
    kwargs = {"sort_keys": True}
    if pretty:
        kwargs["indent"] = 2
    return json.dumps(to_jsonable(data), **kwargs)


def file_size_bytes(path: str | Path) -> int:
    return Path(path).stat().st_size


def is_file_size_stable(
    path: str | Path, checks: int = 2, interval_sec: float = 0.5
) -> bool:
    if checks < 2:
        raise ValueError("checks must be at least 2")

    try:
        previous_size = file_size_bytes(path)
        for _ in range(checks - 1):
            time.sleep(interval_sec)
            current_size = file_size_bytes(path)
            if current_size != previous_size:
                return False
            previous_size = current_size
    except OSError:
        return False
    return True

