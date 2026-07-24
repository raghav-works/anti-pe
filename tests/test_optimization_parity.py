import inspect

import numpy as np
from sklearn.feature_extraction import FeatureHasher

from anti_pe_scanner.ember_v2_features import (
    ByteEntropyHistogram,
    ImportsInfo,
    PEFeatureExtractorV2,
    StringExtractor,
)
from anti_pe_scanner.prepared_pe import prepare_pe_file


def test_byte_entropy_uses_official_coarse_histogram_semantics():
    feature = ByteEntropyHistogram()
    block = np.arange(256, dtype=np.uint8).repeat(8)
    entropy_bin, counts = feature._entropy_bin_counts(block)
    assert entropy_bin == 15
    np.testing.assert_array_equal(counts, np.full(16, 128))


def test_string_group_has_official_104_value_order():
    raw = StringExtractor().raw_features(
        b"hello MZ https://example.test C:\\Windows HKEY_TEST", None
    )
    vector = StringExtractor().process_raw_features(raw)
    assert vector.shape == (104,)
    assert vector[0] == 1
    assert vector[2] == raw["printables"]
    assert vector[-4:].tolist() == [1, 1, 1, 1]


def test_import_hashing_is_sklearn_feature_hasher():
    raw = {"KERNEL32.dll": ["CreateFileW", "ordinal7"]}
    actual = ImportsInfo().process_raw_features(raw)
    expected_libraries = FeatureHasher(256, input_type="string").transform(
        [["kernel32.dll"]]
    ).toarray()[0]
    expected_imports = FeatureHasher(1024, input_type="string").transform(
        [["kernel32.dll:CreateFileW", "kernel32.dll:ordinal7"]]
    ).toarray()[0]
    np.testing.assert_array_equal(actual, np.hstack([expected_libraries, expected_imports]))


def test_extractor_has_natural_official_dimension():
    assert PEFeatureExtractorV2.dim == 2381
    assert sum(feature.dim for feature in PEFeatureExtractorV2.feature_types) == 2381


def test_large_input_parser_source_never_builds_byte_list():
    source = inspect.getsource(prepare_pe_file)
    assert "list(raw_bytes)" not in source
    assert "lief.PE.parse(raw_bytes)" in source
