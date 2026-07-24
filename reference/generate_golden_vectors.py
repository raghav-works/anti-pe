"""Generate vectors with the official Elastic EMBER checkout mounted at /ember."""

import argparse
import hashlib
import json
from pathlib import Path

import ember
import lief
import numpy as np
import sklearn


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    source, output = Path(args.file), Path(args.output_dir)
    bytez = source.read_bytes()
    vector = ember.PEFeatureExtractor(feature_version=2).feature_vector(bytez)
    output.mkdir(parents=True, exist_ok=True)
    vector_path = output / (source.stem + ".npy")
    np.save(str(vector_path), vector.astype(np.float32))
    manifest = {
        "sample_sha256": hashlib.sha256(bytez).hexdigest(),
        "sample_type": "windows_pe",
        "reference_extractor": "official_ember_v2",
        "official_ember_commit": "d97a0b523de02f3fe5ea6089d080abacab6ee931",
        "reference_lief": lief.__version__,
        "numpy": np.__version__,
        "scikit_learn": sklearn.__version__,
        "vector_file": vector_path.name,
        "vector_sha256": hashlib.sha256(vector_path.read_bytes()).hexdigest(),
        "feature_dim": int(vector.shape[0]),
    }
    (output / (source.stem + ".json")).write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()

