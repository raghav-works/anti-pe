import json

from anti_pe_scanner.errors import ACTION_NONE, STATUS_SUCCESS, VERDICT_ALLOW
from anti_pe_scanner.event_builder import build_event
from anti_pe_scanner.schemas import DecisionInfo, FileInfo, ModelInfo
from anti_pe_scanner.utils import safe_json_dumps


def test_build_event_output_is_json_serializable():
    event = build_event(
        STATUS_SUCCESS,
        file_info=FileInfo(path="/tmp/clean.exe", size_bytes=123, sha256="abc"),
        model_info=ModelInfo(model_name="lightgbm_pe_malware_detector", score=0.1),
        decision_info=DecisionInfo(verdict=VERDICT_ALLOW, action=ACTION_NONE, score=0.1),
        host_context={"agent_id": "test-agent"},
    )

    encoded = safe_json_dumps(event)
    decoded = json.loads(encoded)

    assert decoded["event_type"] == "ml_pe_scan"
    assert decoded["host_context"]["agent_id"] == "test-agent"
