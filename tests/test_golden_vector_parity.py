import json
from pathlib import Path

import numpy as np
import pytest

from anti_pe_scanner.ember_v2_features import FEATURE_OFFSETS
from anti_pe_scanner.feature_extractor import PEFeatureExtractor
from anti_pe_scanner.prepared_pe import prepare_pe_file

GOLDEN_DIR = Path("tests/golden")


def test_golden_manifest_is_honest_and_versioned():
    manifest = json.loads((GOLDEN_DIR / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["reference_extractor"] == "official_ember_v2"
    assert manifest["reference_lief"] == "0.9.0"
    assert manifest["feature_dim"] == 2381


@pytest.mark.parametrize(
    "sample",
    json.loads((GOLDEN_DIR / "manifest.json").read_text(encoding="utf-8"))["samples"],
)
def test_runtime_full_vector_and_each_group_match_golden(sample):
    source = Path(sample["source_file"])
    golden = np.load(GOLDEN_DIR / sample["vector_file"], allow_pickle=False)
    runtime = PEFeatureExtractor().extract_prepared(prepare_pe_file(source)).reshape(-1)
    np.testing.assert_allclose(runtime, golden, rtol=0, atol=1e-6)
    for start, end in FEATURE_OFFSETS.values():
        np.testing.assert_allclose(
            runtime[start:end], golden[start:end], rtol=0, atol=1e-6
        )
