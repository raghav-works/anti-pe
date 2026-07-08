"""Build JSON-serializable scan events."""

from __future__ import annotations

from typing import Any

from anti_pe_scanner.schemas import to_jsonable
from anti_pe_scanner.utils import utc_now_iso


def build_event(
    scan_status: str,
    file_info: Any = None,
    model_info: Any = None,
    decision_info: Any = None,
    error: Any = None,
    host_context: Any = None,
) -> dict[str, Any]:
    event = {
        "event_type": "ml_pe_scan",
        "event_version": "1.0",
        "timestamp": utc_now_iso(),
        "scan_status": scan_status,
        "file": to_jsonable(file_info) if file_info is not None else None,
        "model": to_jsonable(model_info) if model_info is not None else None,
        "decision": to_jsonable(decision_info) if decision_info is not None else None,
        "error": to_jsonable(error) if error is not None else None,
    }

    if host_context is not None:
        event["host_context"] = to_jsonable(host_context)

    return event

