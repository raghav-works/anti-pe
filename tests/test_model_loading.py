import numpy as np
import pytest

from anti_pe_scanner.model_loader import EXPECTED_FEATURE_DIM, LightGBMModelPackage

MODEL_PACKAGE_PATH = "models/lightgbm_pe_v1"


@pytest.fixture(scope="module")
def loaded_model_package():
    package = LightGBMModelPackage(MODEL_PACKAGE_PATH)
    package.load()
    return package


def test_model_package_loads_successfully(loaded_model_package):
    assert loaded_model_package.model is not None


def test_metadata_loads_correctly(loaded_model_package):
    assert loaded_model_package.metadata["model_name"] == "lightgbm_pe_malware_detector"
    assert loaded_model_package.metadata["model_type"] == "lightgbm"


def test_thresholds_load_correctly(loaded_model_package):
    thresholds = loaded_model_package.thresholds

    assert thresholds["alert_threshold"] == pytest.approx(0.6242529630641415)
    assert thresholds["block_threshold"] == pytest.approx(0.9385114343804422)


def test_feature_config_has_expected_feature_dim(loaded_model_package):
    assert loaded_model_package.feature_config["feature_dim"] == EXPECTED_FEATURE_DIM


def test_wrong_feature_shape_raises_value_error(loaded_model_package):
    wrong_features = np.zeros((1, EXPECTED_FEATURE_DIM - 1), dtype=np.float32)

    with pytest.raises(ValueError, match="features must have shape"):
        loaded_model_package.predict_score(wrong_features)


def test_random_feature_vector_prediction_returns_probability_float(loaded_model_package):
    # This only validates model loading and prediction plumbing, not detection quality.
    rng = np.random.default_rng(seed=7)
    features = rng.random((1, EXPECTED_FEATURE_DIM), dtype=np.float32)

    score = loaded_model_package.predict_score(features)

    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0
