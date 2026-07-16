"""Persistent JSON-lines scanner worker and reusable subprocess client."""

from __future__ import annotations

import json
import subprocess
import threading
from pathlib import Path
from typing import Any, TextIO

from anti_pe_scanner.scanner import PEMalwareScanner
from anti_pe_scanner.utils import safe_json_dumps


def run_jsonl_server(
    scanner: PEMalwareScanner,
    input_stream: TextIO,
    output_stream: TextIO,
    error_stream: TextIO,
) -> int:
    for line in input_stream:
        request_id: Any = None
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("request must be a JSON object")
            request_id = request.get("request_id")
            if request.get("command") == "shutdown":
                print(
                    safe_json_dumps({"request_id": request_id, "shutdown": True}),
                    file=output_stream,
                    flush=True,
                )
                return 0
            file_path = request.get("file_path")
            if not isinstance(file_path, str) or not file_path:
                raise ValueError("file_path must be a non-empty string")
            event = scanner.scan_file(
                file_path,
                policy=request.get("policy"),
                host_context=request.get("host_context"),
                include_telemetry=bool(request.get("include_telemetry", False)),
                trusted_sha256=request.get("sha256"),
            )
            response = {"request_id": request_id, "event": event}
        except Exception as exc:
            print(f"server request failed: {exc}", file=error_stream, flush=True)
            response = {
                "request_id": request_id,
                "error": {"code": "invalid_request", "message": str(exc)},
            }
        print(safe_json_dumps(response), file=output_stream, flush=True)
    return 0


class ScannerWorkerClient:
    """Small synchronous client suitable for an Agent integration."""

    def __init__(self, command: list[str], timeout_sec: float = 30.0) -> None:
        self.command = command
        self.timeout_sec = timeout_sec
        self._lock = threading.Lock()
        self.process: subprocess.Popen[str] | None = None

    def start(self) -> None:
        if self.process is not None and self.process.poll() is None:
            return
        self.process = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def scan(
        self,
        file_path: str | Path,
        request_id: str,
        host_context: dict[str, Any] | None = None,
        sha256: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            self.start()
            assert self.process is not None
            assert self.process.stdin is not None
            assert self.process.stdout is not None
            request = {
                "request_id": request_id,
                "file_path": str(file_path),
                "host_context": host_context or {},
                "sha256": sha256,
            }
            self.process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
            self.process.stdin.flush()
            # readline is intentionally synchronous; Agent callers should wrap
            # this client in their existing timeout/cancellation primitive.
            line = self.process.stdout.readline()
            if not line:
                returncode = self.process.poll()
                self.process = None
                raise RuntimeError(f"scanner worker exited unexpectedly ({returncode})")
            return json.loads(line)

    def close(self) -> None:
        with self._lock:
            if self.process is None:
                return
            if self.process.poll() is None and self.process.stdin and self.process.stdout:
                self.process.stdin.write('{"request_id":"shutdown","command":"shutdown"}\n')
                self.process.stdin.flush()
                self.process.stdout.readline()
                self.process.wait(timeout=self.timeout_sec)
            self.process = None
