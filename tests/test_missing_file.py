from anti_pe_scanner.errors import STATUS_FILE_NOT_FOUND, STATUS_READ_ERROR
from anti_pe_scanner.pe_validator import validate_pe_file


def test_missing_file_returns_file_not_found(tmp_path):
    missing_path = tmp_path / "does_not_exist.exe"

    result = validate_pe_file(missing_path)

    assert result.is_valid_pe is False
    assert result.scan_status == STATUS_FILE_NOT_FOUND
    assert result.file_path == str(missing_path)
    assert result.error_message


def test_directory_path_does_not_crash(tmp_path):
    result = validate_pe_file(tmp_path)

    assert result.is_valid_pe is False
    assert result.scan_status == STATUS_READ_ERROR
    assert result.error_message
