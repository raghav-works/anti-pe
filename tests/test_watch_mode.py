import argparse
import io
import json
from types import SimpleNamespace

import pytest

from anti_pe_scanner.errors import STATUS_SKIPPED_NOT_PE
from tools import scan_file
from tools import watch_dir


class DummyScanner:
    def __init__(self) -> None:
        self.scanned = []

    def scan_file(self, path):
        self.scanned.append(str(path))
        return {
            "event_type": "ml_pe_scan",
            "event_version": "1.0",
            "timestamp": "2026-07-08T00:00:00Z",
            "scan_status": STATUS_SKIPPED_NOT_PE,
            "file": {"path": str(path)},
            "model": None,
            "decision": None,
            "error": None,
        }


def test_cli_parser_rejects_file_and_watch_dir_together():
    with pytest.raises(SystemExit):
        scan_file.parse_args(["--file", "a.exe", "--watch-dir", "samples"])


def test_watch_state_avoids_duplicate_unchanged_file_scans(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"one")
    state = watch_dir.FileScanState()

    assert state.should_scan(sample) is True
    assert state.should_scan(sample) is False

    sample.write_bytes(b"changed")
    assert state.should_scan(sample) is True


def test_wait_until_file_stable_uses_size_stability_helper(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"content")
    calls = []

    def fake_is_file_size_stable(path, checks=2, interval_sec=0.5):
        calls.append((path, checks, interval_sec))
        return True

    monkeypatch.setattr(watch_dir, "is_file_size_stable", fake_is_file_size_stable)

    assert watch_dir.wait_until_file_stable(sample, retries=1, interval_sec=0.01) is True
    assert calls


def test_watch_handler_calls_scanner_for_new_file_event(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"content")
    scanner = DummyScanner()
    output = io.StringIO()
    handler = watch_dir.WatchModeEventHandler(scanner=scanner, output_stream=output)

    monkeypatch.setattr(watch_dir, "wait_until_file_stable", lambda path: True)
    handler.on_created(SimpleNamespace(is_directory=False, src_path=str(sample)))

    assert scanner.scanned == [str(sample)]
    event = json.loads(output.getvalue())
    assert event["scan_status"] == STATUS_SKIPPED_NOT_PE


def test_watch_handler_does_not_crash_if_file_disappears(tmp_path, monkeypatch):
    missing = tmp_path / "gone.bin"
    scanner = DummyScanner()
    output = io.StringIO()
    handler = watch_dir.WatchModeEventHandler(scanner=scanner, output_stream=output)

    monkeypatch.setattr(watch_dir, "wait_until_file_stable", lambda path: True)
    handler.on_modified(SimpleNamespace(is_directory=False, src_path=str(missing)))

    assert scanner.scanned == []
    assert output.getvalue() == ""


def test_scan_path_once_skips_duplicate_unchanged_file(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"content")
    scanner = DummyScanner()
    state = watch_dir.FileScanState()
    output = io.StringIO()

    monkeypatch.setattr(watch_dir, "wait_until_file_stable", lambda path: True)

    first = watch_dir.scan_path_once(scanner, sample, state, output_stream=output)
    second = watch_dir.scan_path_once(scanner, sample, state, output_stream=output)

    assert first is not None
    assert second is None
    assert scanner.scanned == [str(sample)]
