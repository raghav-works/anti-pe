import hashlib

import pytest

from anti_pe_scanner.errors import STATUS_SKIPPED_TOO_LARGE
from anti_pe_scanner.prepared_pe import PEPreparationError, prepare_pe_file


def test_oversized_file_is_rejected_before_read_hash_or_parse(tmp_path, monkeypatch):
    sample = tmp_path / "oversized.exe"
    sample.write_bytes(b"MZ")

    def fail_read(*args, **kwargs):
        raise AssertionError("oversized file must not be read")

    monkeypatch.setattr(type(sample), "read_bytes", fail_read)
    with pytest.raises(PEPreparationError) as caught:
        prepare_pe_file(sample, max_file_size_mb=0)
    assert caught.value.scan_status == STATUS_SKIPPED_TOO_LARGE
    assert caught.value.sha256 is None
    assert "lief_parse_ms" not in caught.value.timings_ms


def test_prepared_real_pe_is_read_hashed_and_parsed_once():
    path = "samples/large/vlc-3.0.23-win64.exe"
    prepared = prepare_pe_file(path)
    assert prepared.size_bytes == len(prepared.raw_bytes)
    assert prepared.sha256 == hashlib.sha256(prepared.raw_bytes).hexdigest()
    assert prepared.lief_binary is not None
    assert "file_read_ms" in prepared.timings_ms
    assert "lief_parse_ms" in prepared.timings_ms
