"""Compare one runtime EMBER vector with a historical golden vector."""

from __future__ import annotations

import argparse
import json

import numpy as np

from anti_pe_scanner.ember_v2_features import FEATURE_OFFSETS
from anti_pe_scanner.feature_extractor import PEFeatureExtractor
from anti_pe_scanner.model_loader import LightGBMModelPackage
from anti_pe_scanner.policy import load_policy, merge_policy
from anti_pe_scanner.prepared_pe import prepare_pe_file
from anti_pe_scanner.verdict import decide_verdict


def _group(index: int | None) -> str | None:
    if index is None:
        return None
    return next(
        (name for name, (start, end) in FEATURE_OFFSETS.items() if start <= index < end),
        None,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    parser.add_argument("--golden-vector", required=True)
    parser.add_argument("--model-package", required=True)
    args = parser.parse_args()

    runtime = PEFeatureExtractor().extract_prepared(
        prepare_pe_file(args.file)
    ).reshape(-1)
    golden = np.load(args.golden_vector, allow_pickle=False).reshape(-1).astype(np.float32)
    common = min(runtime.size, golden.size)
    delta = np.abs(runtime[:common] - golden[:common])
    differing = np.flatnonzero(delta > 0)
    first = int(differing[0]) if differing.size else None
    package = LightGBMModelPackage(args.model_package)
    package.load()
    runtime_score = package.predict_score(runtime)
    golden_score = package.predict_score(golden)
    policy = merge_policy(load_policy(None), package.thresholds)
    per_group = {}
    for name, (start, end) in FEATURE_OFFSETS.items():
        part = np.abs(runtime[start:end] - golden[start:end])
        per_group[name] = {
            "differing_values": int(np.count_nonzero(part)),
            "maximum_absolute_difference": float(part.max(initial=0)),
        }
    result = {
        "runtime_feature_dimension": int(runtime.size),
        "golden_feature_dimension": int(golden.size),
        "exact_equality": bool(np.array_equal(runtime, golden)),
        "allclose": bool(np.allclose(runtime, golden, rtol=0, atol=1e-6)),
        "differing_values": int(differing.size),
        "maximum_absolute_difference": float(delta.max(initial=0)),
        "mean_absolute_difference": float(delta.mean()) if common else 0.0,
        "first_differing_index": first,
        "first_differing_group": _group(first),
        "differences_per_feature_group": per_group,
        "golden_model_score": golden_score,
        "runtime_model_score": runtime_score,
        "score_difference": runtime_score - golden_score,
        "golden_verdict": decide_verdict(golden_score, policy).verdict,
        "runtime_verdict": decide_verdict(runtime_score, policy).verdict,
    }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
