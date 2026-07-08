from anti_pe_scanner.errors import ACTION_NONE, STATUS_SUCCESS, VERDICT_ALERT
from anti_pe_scanner.event_builder import build_event
from anti_pe_scanner.schemas import DecisionInfo, FileInfo, ModelInfo


def test_build_event_always_includes_required_top_level_fields():
    event = build_event(STATUS_SUCCESS)

    assert event["event_type"] == "ml_pe_scan"
    assert event["event_version"] == "1.0"
    assert "timestamp" in event
    assert event["scan_status"] == STATUS_SUCCESS
    assert "file" in event
    assert "model" in event
    assert "decision" in event
    assert "error" in event


def test_build_event_serializes_dataclass_sections():
    event = build_event(
        STATUS_SUCCESS,
        file_info=FileInfo(path="/tmp/sample.exe", size_bytes=12),
        model_info=ModelInfo(model_name="lightgbm_pe_malware_detector", score=0.7),
        decision_info=DecisionInfo(verdict=VERDICT_ALERT, action=ACTION_NONE, score=0.7),
    )

    assert event["file"]["path"] == "/tmp/sample.exe"
    assert event["model"]["score"] == 0.7
    assert event["decision"]["verdict"] == VERDICT_ALERT
