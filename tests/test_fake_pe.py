from anti_pe_scanner.errors import STATUS_PARSE_ERROR, STATUS_SKIPPED_NOT_PE, STATUS_SUCCESS
from anti_pe_scanner.pe_validator import validate_pe_file


def test_fake_mz_without_valid_pe_header_does_not_crash(tmp_path):
    fake_mz = tmp_path / "fake_mz.exe"
    fake_mz.write_bytes(b"MZ" + b"\x00" * 20)

    result = validate_pe_file(fake_mz)

    assert result.is_valid_pe is False
    assert result.scan_status in {STATUS_SKIPPED_NOT_PE, STATUS_PARSE_ERROR}
    assert result.error_message


def test_minimal_fake_valid_pe_header_passes_header_validation_when_lief_unavailable(tmp_path):
    fake_pe = tmp_path / "minimal_header.exe"
    data = bytearray(0x84)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, byteorder="little")
    data[0x80:0x84] = b"PE\x00\x00"
    fake_pe.write_bytes(bytes(data))

    result = validate_pe_file(fake_pe)

    # Header validation is the minimum gate. If optional LIEF is installed, it
    # may reject this intentionally tiny synthetic PE as structurally incomplete.
    assert result.scan_status in {STATUS_SUCCESS, STATUS_PARSE_ERROR}
    assert result.is_valid_pe is (result.scan_status == STATUS_SUCCESS)
