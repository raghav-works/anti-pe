import json
import subprocess
import sys

import pytest

import anti_pe_scanner.scanner as scanner_module
from anti_pe_scanner.errors import (
    STATUS_FEATURE_ERROR,
    STATUS_FILE_NOT_FOUND,
    STATUS_POLICY_DISABLED,
    STATUS_SKIPPED_NOT_PE,
    STATUS_SUCCESS,
)
from anti_pe_scanner.feature_extractor import FeatureExtractionError
from anti_pe_scanner.scanner import PEMalwareScanner
from anti_pe_scanner.schemas import ValidationResult
from anti_pe_scanner.utils import safe_json_dumps

MODEL_PACKAGE_PATH = "models/lightgbm_pe_v1"


@pytest.fixture()
def scanner():
    return PEMalwareScanner(MODEL_PACKAGE_PATH)


def test_missing_file_returns_file_not_found(scanner, tmp_path):
    event = scanner.scan_file(tmp_path / "missing.exe")

    assert event["scan_status"] == STATUS_FILE_NOT_FOUND
    assert event["error"]["code"] == STATUS_FILE_NOT_FOUND


def test_non_pe_text_file_returns_skipped_not_pe(scanner, tmp_path):
    text_file = tmp_path / "notes.txt"
    text_file.write_text("hello", encoding="utf-8")

    event = scanner.scan_file(text_file)

    assert event["scan_status"] == STATUS_SKIPPED_NOT_PE
    assert event["file"]["type"] == "non_pe"
    assert event["decision"] is None


def test_policy_disabled_returns_policy_disabled(scanner, tmp_path):
    text_file = tmp_path / "notes.txt"
    text_file.write_text("hello", encoding="utf-8")

    event = scanner.scan_file(text_file, policy={"scan_enabled": False})

    assert event["scan_status"] == STATUS_POLICY_DISABLED
    assert event["error"] is None


def test_scanner_does_not_call_model_inference_for_non_pe(scanner, tmp_path, monkeypatch):
    text_file = tmp_path / "notes.txt"
    text_file.write_text("hello", encoding="utf-8")

    def fail_predict(_features):
        raise AssertionError("model inference should not be called for non-PE files")

    monkeypatch.setattr(scanner.model_package, "predict_score", fail_predict)

    event = scanner.scan_file(text_file)

    assert event["scan_status"] == STATUS_SKIPPED_NOT_PE


def test_feature_extraction_error_returns_feature_error(scanner, tmp_path, monkeypatch):
    fake_pe = tmp_path / "sample.exe"
    fake_pe.write_bytes(b"MZ" + b"\x00" * 128)

    class FakePrepared:
        path = fake_pe
        name = "sample.exe"
        size_bytes = fake_pe.stat().st_size
        raw_bytes = fake_pe.read_bytes()
        sha256 = "abc"
        lief_binary = object()
        timings_ms = {}

    def fake_prepare(file_path, max_file_size_mb=100):
        return FakePrepared()

    def fail_extract(_prepared, _timings):
        raise FeatureExtractionError("synthetic extraction failure")

    monkeypatch.setattr(scanner_module, "prepare_pe_file", fake_prepare)
    monkeypatch.setattr(scanner.feature_extractor, "extract_prepared", fail_extract)

    event = scanner.scan_file(fake_pe)

    assert event["scan_status"] == STATUS_FEATURE_ERROR
    assert event["error"]["code"] == STATUS_FEATURE_ERROR
    assert "synthetic extraction failure" in event["error"]["message"]


def test_scanner_event_is_json_serializable(scanner, tmp_path):
    text_file = tmp_path / "notes.txt"
    text_file.write_text("hello", encoding="utf-8")

    encoded = safe_json_dumps(scanner.scan_file(text_file))
    decoded = json.loads(encoded)

    assert decoded["event_type"] == "ml_pe_scan"
    assert decoded["scan_status"] == STATUS_SKIPPED_NOT_PE


def test_cli_runs_on_non_pe_file_and_returns_json_exit_zero(tmp_path):
    text_file = tmp_path / "notes.txt"
    text_file.write_text("hello", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "tools/scan_file.py",
            "--file",
            str(text_file),
            "--model-package",
            MODEL_PACKAGE_PATH,
        ],
        cwd=".",
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    event = json.loads(result.stdout)
    assert event["scan_status"] == STATUS_SKIPPED_NOT_PE


def test_success_path_real_pe_sample_pending():
    sample = "samples/benign_wxc_test_proxy.exe"
    try:
        open(sample, "rb").close()
    except OSError:
        pytest.skip("Requires a known benign real PE sample in samples/.")

    scanner = PEMalwareScanner(MODEL_PACKAGE_PATH)
    event = scanner.scan_file(sample)

    assert event["scan_status"] == STATUS_SUCCESS
    assert event["file"]["type"] == "windows_pe"
    assert isinstance(event["model"]["score"], float)
    assert 0.0 <= event["model"]["score"] <= 1.0
    assert event["decision"]["verdict"] in {"allow", "alert", "block", "log"}
    assert event["error"] is None
