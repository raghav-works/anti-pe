"""Map model scores and policy into scanner decisions."""

from __future__ import annotations

from anti_pe_scanner.errors import ACTION_BLOCK, ACTION_NONE, VERDICT_ALERT, VERDICT_ALLOW
from anti_pe_scanner.errors import VERDICT_BLOCK, VERDICT_LOG
from anti_pe_scanner.schemas import DecisionInfo, PolicyConfig


def decide_verdict(score: float, policy: PolicyConfig) -> DecisionInfo:
    if score < policy.alert_threshold:
        verdict = VERDICT_ALLOW
        action = ACTION_NONE
    elif score < policy.block_threshold:
        verdict = VERDICT_LOG if policy.mode == "log_only" else VERDICT_ALERT
        action = ACTION_NONE
    elif policy.mode == "block_enabled":
        verdict = VERDICT_BLOCK
        action = ACTION_BLOCK
    elif policy.mode == "log_only":
        verdict = VERDICT_LOG
        action = ACTION_NONE
    else:
        verdict = VERDICT_ALERT
        action = ACTION_NONE

    return DecisionInfo(
        verdict=verdict,
        action=action,
        score=score,
        alert_threshold=policy.alert_threshold,
        block_threshold=policy.block_threshold,
        mode=policy.mode,
    )

