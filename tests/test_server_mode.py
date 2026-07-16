import io
import json

from anti_pe_scanner.scanner import PEMalwareScanner
from anti_pe_scanner.server import run_jsonl_server


def test_server_preserves_ids_continues_after_bad_request_and_stdout_is_jsonl(tmp_path):
    non_pe = tmp_path / "plain.txt"
    non_pe.write_text("hello", encoding="utf-8")
    scanner = PEMalwareScanner("models/lightgbm_pe_v1")
    input_stream = io.StringIO(
        '{"request_id":"bad"}\n'
        + json.dumps({"request_id": "ok", "file_path": str(non_pe)})
        + "\n"
        + '{"request_id":"stop","command":"shutdown"}\n'
    )
    output = io.StringIO()
    errors = io.StringIO()

    assert run_jsonl_server(scanner, input_stream, output, errors) == 0
    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    assert [item["request_id"] for item in responses] == ["bad", "ok", "stop"]
    assert responses[0]["error"]["code"] == "invalid_request"
    assert responses[1]["event"]["scan_status"] == "skipped_not_pe"
    assert responses[2]["shutdown"] is True
    assert "server request failed" in errors.getvalue()


def test_success_cache_is_bounded_and_reports_hit():
    scanner = PEMalwareScanner("models/lightgbm_pe_v1", cache_size=1)
    path = "samples/large/vlc-3.0.23-win64.exe"
    first, first_timing = scanner.scan_file_with_timings(path)
    second, second_timing = scanner.scan_file_with_timings(path)
    assert first["model"]["score"] == second["model"]["score"]
    assert first_timing["cache_hit"] is False
    assert second_timing["cache_hit"] is True
    assert scanner.cache_hits == 1
