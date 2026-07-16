import inspect
import math
import re

import numpy as np

from anti_pe_scanner.feature_extractor import (
    _PEFeatureExtractor,
    _extract_printable_strings,
    _hash_encode,
)
from anti_pe_scanner.prepared_pe import prepare_pe_file


class EmptyLief:
    sections = []
    imports = []
    has_imports = False
    has_exports = False


def _old_entropy_histogram(data_bytes: bytes) -> np.ndarray:
    window_size = 2048
    step = 1024
    hist = np.zeros((16, 16), dtype=np.float32)
    data = np.frombuffer(data_bytes, dtype=np.uint8)
    for start in range(0, max(len(data) - window_size + 1, 1), step):
        window = data[start : start + window_size]
        counts = np.bincount(window, minlength=256)
        probs = counts[counts > 0] / len(window)
        entropy = float(-np.sum(probs * np.log2(probs)))
        entropy_bin = min(int(entropy / 8.0 * 16), 15)
        byte_hist, _ = np.histogram(window, bins=16, range=(0, 256))
        hist[entropy_bin] += byte_hist / max(byte_hist.sum(), 1)
    return (hist / max(hist.sum(), 1)).flatten().astype(np.float32)


def _old_string_features(data: bytes) -> np.ndarray:
    strings = _extract_printable_strings(data, 5)
    lengths = [len(value) for value in strings]
    if lengths:
        hist, _ = np.histogram(
            [math.log2(max(length, 1)) for length in lengths], bins=10, range=(0, 10)
        )
    else:
        hist = np.zeros(10, dtype=np.float32)
    joined = b"\n".join(strings)
    scalars = np.array(
        [
            len(strings),
            float(np.mean(lengths)) if lengths else 0.0,
            len(re.findall(rb"https?://", joined)),
            len(re.findall(rb"HKEY_|SOFTWARE\\|SYSTEM\\", joined)),
            len(re.findall(rb"[Cc]:\\|[Ss]ystem32", joined)),
            len(re.findall(rb"MZ", joined)),
            min(lengths) if lengths else 0,
            max(lengths) if lengths else 0,
            float(np.std(lengths)) if lengths else 0,
            float(np.median(lengths)) if lengths else 0,
        ],
        dtype=np.float32,
    )
    result = np.concatenate([hist.astype(np.float32), scalars])
    return np.pad(result, (0, 104 - len(result))).astype(np.float32)


def test_entropy_optimization_is_exact_for_edge_and_random_inputs():
    rng = np.random.default_rng(42)
    inputs = [
        b"A",
        bytes(range(256)) * 9,
        rng.integers(0, 256, 8193, dtype=np.uint8).tobytes(),
    ]
    for data in inputs:
        optimized = _PEFeatureExtractor(data, EmptyLief())._byte_entropy_histogram()
        np.testing.assert_array_equal(optimized, _old_entropy_histogram(data))


def test_string_optimization_is_exact_and_does_not_join_strings():
    data = (
        b"\x00hello MZ https://example.test\x00"
        b"HKEY_LOCAL_MACHINE SOFTWARE\\ SYSTEM\\ C:\\Windows\\System32\x00"
        b"short\x00" * 20
    )
    extractor = _PEFeatureExtractor(data, EmptyLief())
    np.testing.assert_array_equal(extractor._string_features(), _old_string_features(data))
    assert b".join(" not in inspect.getsource(_PEFeatureExtractor._string_features).encode()


def test_hash_encoding_digest_optimization_preserves_indices():
    names = ["Kernel32.DLL", "CreateRemoteThread", "ümlaut"]
    expected = np.zeros(512, dtype=np.float32)
    import hashlib

    for name in names:
        digest = hashlib.sha256(
            name.lower().encode("utf-8", errors="ignore")
        ).hexdigest()
        expected[int(digest, 16) % 512] = 1.0
    np.testing.assert_array_equal(_hash_encode(names), expected)


def test_large_input_parser_source_never_builds_byte_list():
    source = inspect.getsource(prepare_pe_file)
    assert "list(raw_bytes)" not in source
    assert "lief.PE.parse(raw_bytes)" in source
