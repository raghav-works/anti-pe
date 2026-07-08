# Integration Notes

This scanner is designed for Agent-side inference.

Inputs:

- single file path
- watch directory

Outputs:

- JSON scan event

This repository intentionally excludes training, XGBoost, stacking, meta-classifier, hard mining, SHAP, plotting, notebooks, and large historical artifacts.

Python commands:

```bash
PYTHONPATH=src .venv/bin/python tools/scan_file.py --file sample.exe --model-package models/lightgbm_pe_v1
PYTHONPATH=src .venv/bin/python tools/scan_file.py --watch-dir ./samples --model-package models/lightgbm_pe_v1 --recursive
```

Executable commands:

```bash
anti_pe_scanner.exe --file "C:\path\to\sample.exe"
anti_pe_scanner.exe --watch-dir "C:\Users\Test\Downloads"
```

For v1, continuous mode is folder watching. Final Agent integration may replace folder watching with Agent-provided file events. The model package must stay beside the executable, and the executable performs inference only.

Behavior contract:

- Input is a file path or watch directory.
- Model input is the extracted 2381-feature PE vector.
- Output is JSON.
- Non-PE and invalid files are not scored.
- `block` is reported as a JSON decision only; scanner v1 does not quarantine, delete, or directly block files.
- Training data, EMBER dataset files, and research outputs are not included.
