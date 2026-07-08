from anti_pe_scanner.errors import STATUS_SKIPPED_NOT_PE, STATUS_SKIPPED_TOO_LARGE
from anti_pe_scanner.pe_validator import validate_pe_file


def test_empty_file_returns_skipped_not_pe(tmp_path):
    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")

    result = validate_pe_file(empty_file)

    assert result.is_valid_pe is False
    assert result.scan_status == STATUS_SKIPPED_NOT_PE
    assert result.size_bytes == 0


def test_plain_text_file_returns_skipped_not_pe(tmp_path):
    text_file = tmp_path / "notes.txt"
    text_file.write_text("not a portable executable", encoding="utf-8")

    result = validate_pe_file(text_file)

    assert result.is_valid_pe is False
    assert result.scan_status == STATUS_SKIPPED_NOT_PE
    assert result.error_message == "Missing MZ header"


def test_too_large_file_returns_skipped_too_large(tmp_path):
    oversized_file = tmp_path / "large.bin"
    oversized_file.write_bytes(b"A" * 2)

    result = validate_pe_file(oversized_file, max_file_size_mb=0)

    assert result.is_valid_pe is False
    assert result.scan_status == STATUS_SKIPPED_TOO_LARGE
