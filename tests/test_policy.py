import pytest

from anti_pe_scanner.errors import ACTION_BLOCK, ACTION_NONE
from anti_pe_scanner.errors import VERDICT_ALERT, VERDICT_ALLOW, VERDICT_BLOCK
from anti_pe_scanner.policy import load_policy, validate_policy
from anti_pe_scanner.schemas import PolicyConfig
from anti_pe_scanner.verdict import decide_verdict


def test_default_policy_loads():
    policy = load_policy(None)

    assert policy.scan_enabled is True
    assert policy.mode == "alert_only"
    assert policy.alert_threshold < policy.block_threshold


def test_invalid_mode_raises_value_error():
    with pytest.raises(ValueError, match="Invalid policy mode"):
        validate_policy(PolicyConfig(mode="observe_and_vibes"))


def test_alert_threshold_greater_than_or_equal_to_block_threshold_raises():
    with pytest.raises(ValueError, match="alert_threshold must be less"):
        validate_policy(PolicyConfig(alert_threshold=0.8, block_threshold=0.8))


def test_score_below_alert_threshold_returns_allow():
    policy = PolicyConfig(alert_threshold=0.5, block_threshold=0.9)

    decision = decide_verdict(0.49, policy)

    assert decision.verdict == VERDICT_ALLOW
    assert decision.action == ACTION_NONE


def test_score_between_thresholds_returns_alert_in_alert_only_mode():
    policy = PolicyConfig(mode="alert_only", alert_threshold=0.5, block_threshold=0.9)

    decision = decide_verdict(0.7, policy)

    assert decision.verdict == VERDICT_ALERT
    assert decision.action == ACTION_NONE


def test_score_above_block_threshold_returns_alert_in_alert_only_mode():
    policy = PolicyConfig(mode="alert_only", alert_threshold=0.5, block_threshold=0.9)

    decision = decide_verdict(0.95, policy)

    assert decision.verdict == VERDICT_ALERT
    assert decision.action == ACTION_NONE


def test_score_above_block_threshold_returns_block_in_block_enabled_mode():
    policy = PolicyConfig(mode="block_enabled", alert_threshold=0.5, block_threshold=0.9)

    decision = decide_verdict(0.95, policy)

    assert decision.verdict == VERDICT_BLOCK
    assert decision.action == ACTION_BLOCK
