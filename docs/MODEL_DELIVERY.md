# Model Delivery

The bundled model is a LightGBM PE malware detector.

Model package:

- `models/lightgbm_pe_v1/model.txt`
- `models/lightgbm_pe_v1/metadata.json`
- `models/lightgbm_pe_v1/thresholds.json`
- `models/lightgbm_pe_v1/feature_config.json`

The feature extractor must preserve the same 2381-feature order expected by the trained model.

TODO: run feature parity testing against the old Anti_PE ((2)) POC extractor on known benign PE files. The same file should produce the same 2381-feature vector before this scanner is treated as production-ready.

## Packaged Layout

The v1 executable does not embed the model. The model package must stay beside the executable:

```text
dist/
  anti_pe_scanner.exe
  models/
    lightgbm_pe_v1/
      model.txt
      metadata.json
      thresholds.json
      feature_config.json
```

The package is inference-only and does not include training data.

Thresholds:

- alert: `0.6242529630641415`
- block: `0.9385114343804422`

The LightGBM model is loaded from `model.txt` with `lightgbm.Booster(model_file=...)`. No training occurs in this project.
