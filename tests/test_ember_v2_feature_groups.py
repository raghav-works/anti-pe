import numpy as np

from anti_pe_scanner.ember_v2_features import (
    EMBER_V2_DIM,
    FEATURE_GROUPS,
    PEFeatureExtractorV2,
)
from anti_pe_scanner.prepared_pe import prepare_pe_file


def test_every_official_group_has_declared_dimension_on_real_pe():
    prepared = prepare_pe_file("samples/large/vlc-3.0.23-win64.exe")
    extractor = PEFeatureExtractorV2()
    raw = extractor.raw_features(prepared.raw_bytes, prepared.lief_binary)
    for feature, (name, dimension) in zip(extractor.feature_types, FEATURE_GROUPS):
        vector = np.asarray(feature.process_raw_features(raw[name]))
        assert feature.name == name
        assert vector.shape == (dimension,)
    vector = extractor.process_raw_features(raw)
    assert vector.shape == (EMBER_V2_DIM,)
    assert vector.dtype == np.float32
    assert np.isfinite(vector).all()

