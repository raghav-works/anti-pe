"""Continuous folder-watch mode for v1 scanner operation.

This is v1 directory monitoring: it watches a folder for created/modified
files, then passes file paths to the single-file scanner. Final Agent
integration may replace this with Agent-provided file events. The scanner input
is still a file path or watch directory; the model input remains the extracted
2381-feature PE vector.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any, TextIO

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

try:
    from watchdog.events import FileSystemEventHandler as _WatchdogEventHandler
except ImportError:  # Tests can exercise helpers without watchdog installed.
    class _WatchdogEventHandler:  # type: ignore[no-redef]
        pass

from anti_pe_scanner.errors import STATUS_READ_ERROR  # noqa: E402
from anti_pe_scanner.event_builder import build_event  # noqa: E402
from anti_pe_scanner.schemas import FileInfo, ScanError  # noqa: E402
from anti_pe_scanner.utils import is_file_size_stable, safe_json_dumps  # noqa: E402


class FileScanState:
    """Track path, mtime, and size to avoid duplicate unchanged scans."""

    def __init__(self) -> None:
        self._seen: dict[str, tuple[int, int]] = {}

    def should_scan(self, path: str | Path) -> bool:
        path_obj = Path(path)
        try:
            stat = path_obj.stat()
        except OSError:
            return False

        key = str(path_obj.resolve())
        signature = (stat.st_mtime_ns, stat.st_size)
        if self._seen.get(key) == signature:
            return False
        self._seen[key] = signature
        return True


def wait_until_file_stable(
    path: str | Path,
    retries: int = 5,
    interval_sec: float = 0.5,
) -> bool:
    """Wait briefly for a file copy/write to settle before scanning."""
    path_obj = Path(path)
    for _ in range(retries):
        if not path_obj.exists() or not path_obj.is_file():
            return False
        if is_file_size_stable(path_obj, checks=2, interval_sec=interval_sec):
            return True
        time.sleep(interval_sec)
    return False


def scan_path_once(
    scanner: Any,
    path: str | Path,
    state: FileScanState,
    pretty: bool = False,
    output_stream: TextIO | None = None,
) -> dict[str, Any] | None:
    """Scan one stable, changed file and print exactly one JSON event."""
    output = output_stream or sys.stdout
    path_obj = Path(path)

    if not path_obj.exists() or not path_obj.is_file():
        return None
    if not wait_until_file_stable(path_obj):
        return None
    if not state.should_scan(path_obj):
        return None

    try:
        event = scanner.scan_file(path_obj)
    except Exception as exc:
        event = build_event(
            scan_status=STATUS_READ_ERROR,
            file_info=FileInfo(path=str(path_obj), name=path_obj.name, type="unknown"),
            error=ScanError(code=STATUS_READ_ERROR, message=str(exc)),
        )

    print(safe_json_dumps(event, pretty=pretty), file=output, flush=True)
    return event


class WatchModeEventHandler(_WatchdogEventHandler):
    """Handle created/modified file events without stopping on scan errors."""

    def __init__(
        self,
        scanner: Any,
        state: FileScanState | None = None,
        pretty: bool = False,
        output_stream: TextIO | None = None,
    ) -> None:
        super().__init__()
        self.scanner = scanner
        self.state = state or FileScanState()
        self.pretty = pretty
        self.output_stream = output_stream

    def on_created(self, event: Any) -> None:
        self._handle_event(event)

    def on_modified(self, event: Any) -> None:
        self._handle_event(event)

    def _handle_event(self, event: Any) -> None:
        if getattr(event, "is_directory", False):
            return
        src_path = getattr(event, "src_path", None)
        if src_path:
            scan_path_once(self.scanner, src_path, self.state, self.pretty, self.output_stream)


def run_watch_dir(
    watch_dir: str | Path,
    scanner: Any,
    recursive: bool = False,
    pretty: bool = False,
) -> int:
    """Run watchdog observer until Ctrl+C."""
    try:
        from watchdog.observers import Observer
    except ImportError as exc:
        raise RuntimeError("watchdog is required for --watch-dir mode. Install dependency 'watchdog'.") from exc

    watch_path = Path(watch_dir)
    if not watch_path.is_dir():
        raise ValueError(f"Watch path is not a directory: {watch_path}")

    observer = Observer()
    observer.schedule(
        WatchModeEventHandler(scanner=scanner, pretty=pretty),
        str(watch_path),
        recursive=recursive,
    )
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    finally:
        observer.join()
    return 0
