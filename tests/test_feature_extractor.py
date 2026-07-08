import numpy as np
import pytest

from anti_pe_scanner.feature_extractor import (
    EMBER_FEATURE_DIM,
    FeatureExtractionError,
    extract_pe_features,
    _validate_feature_vector,
)


def test_feature_extractor_raises_for_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        extract_pe_features(tmp_path / "missing.exe")


def test_feature_extractor_rejects_empty_file(tmp_path):
    empty_file = tmp_path / "empty.exe"
    empty_file.write_bytes(b"")

    with pytest.raises(FeatureExtractionError, match="empty"):
        extract_pe_features(empty_file)


def test_feature_extractor_rejects_plain_text_file(tmp_path):
    text_file = tmp_path / "notes.txt"
    text_file.write_text("not a PE", encoding="utf-8")

    with pytest.raises(FeatureExtractionError):
        extract_pe_features(text_file)


def test_minimal_fake_pe_raises_clear_extraction_error(tmp_path):
    fake_pe = tmp_path / "minimal_header.exe"
    data = bytearray(0x84)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, byteorder="little")
    data[0x80:0x84] = b"PE\x00\x00"
    fake_pe.write_bytes(bytes(data))

    with pytest.raises(FeatureExtractionError):
        extract_pe_features(fake_pe)


def test_validate_feature_vector_accepts_correct_shape():
    features = np.zeros((1, EMBER_FEATURE_DIM), dtype=np.float32)

    validated = _validate_feature_vector(features)

    assert validated.shape == (1, EMBER_FEATURE_DIM)
    assert validated.dtype == np.float32


def test_validate_feature_vector_accepts_flat_vector_and_reshapes():
    features = np.zeros(EMBER_FEATURE_DIM, dtype=np.float32)

    validated = _validate_feature_vector(features)

    assert validated.shape == (1, EMBER_FEATURE_DIM)


def test_validate_feature_vector_rejects_wrong_length():
    features = np.zeros(EMBER_FEATURE_DIM - 1, dtype=np.float32)

    with pytest.raises(ValueError, match="Feature vector must have shape"):
        _validate_feature_vector(features)


def test_validate_feature_vector_rejects_nan_or_inf():
    features = np.zeros((1, EMBER_FEATURE_DIM), dtype=np.float32)
    features[0, 10] = np.nan

    with pytest.raises(ValueError, match="NaN or infinite"):
        _validate_feature_vector(features)

