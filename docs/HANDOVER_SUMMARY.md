# Handover Summary

## Project

Anti-PE LightGBM Agent Scanner.

## Purpose

This project is a LightGBM-only Agent-side Windows PE malware scanner. It is inference-only and emits JSON events for single-file scans and continuous folder watch mode.

The scanner input is a file path or watch directory. The model input is not the raw file; it is the 2381 numerical PE feature vector extracted from a validated Windows PE file.

## Reused From Anti_PE ((2))

- LightGBM model artifact from `outputs/runs/20260604_104958_both/lightgbm/model.txt`
- Validation-tuned thresholds from the same LightGBM run
- Model metadata references from the same run
- Feature extraction logic adapted from `features/extractor.py`
- Scanner flow concepts from `scanner/scan.py` and `scan_file.py`

## Deliberately Excluded

- XGBoost
- Stacking and meta-classifiers
- Hard mining and OOF artifacts
- SHAP, plots, notebooks, and research reports
- Training pipeline code
- EMBER dataset files
- Large prediction CSVs and historical run artifacts
- Malware samples

## Model Package

Location:

```text
models/lightgbm_pe_v1/
  model.txt
  metadata.json
  thresholds.json
  feature_config.json
```

Details:

- Model type: LightGBM
- Feature dimension: `2381`
- Feature version: `ember_feature_version_2`
- Alert threshold: `0.6242529630641415`
- Block threshold: `0.9385114343804422`
- Loader: `lightgbm.Booster(model_file=...)`
- Training is not performed in this project.

## Run Commands

Python single-file mode:

```bash
PYTHONPATH=src .venv/bin/python tools/scan_file.py --file README.md --model-package models/lightgbm_pe_v1 --pretty
```

Python continuous watch mode:

```bash
PYTHONPATH=src .venv/bin/python tools/scan_file.py --watch-dir ./samples --model-package models/lightgbm_pe_v1 --recursive --pretty
```

Packaged single-file mode on Linux:

```bash
dist/anti_pe_scanner --file README.md --pretty
```

Packaged single-file mode on Windows:

```powershell
anti_pe_scanner.exe --file "C:\path\to\sample.exe"
```

Packaged continuous mode on Windows:

```powershell
anti_pe_scanner.exe --watch-dir "C:\Users\Test\Downloads"
```

Stop continuous mode with Ctrl+C.

## Build Commands

Linux/source build:

```bash
PYTHONPATH=src .venv/bin/python tools/build_exe.py
```

Windows executable build:

```powershell
.venv\Scripts\python.exe tools\build_exe.py
```

PyInstaller builds for the current OS. A Windows `.exe` must be built on Windows or in a Windows build environment.

## Distribution Layout

```text
dist/
  anti_pe_scanner or anti_pe_scanner.exe
  models/lightgbm_pe_v1/
  configs/policy.json
  docs/
```

The model package must stay beside the executable.

## Current Validation Status

- Unit and integration tests pass.
- Non-PE files return `skipped_not_pe`.
- Missing files return `file_not_found`.
- Empty/fake PE files do not crash.
- Non-PE files do not reach feature extraction or model inference.
- A benign PE sample validated the full success path: PE validation, LIEF feature extraction, LightGBM scoring, verdict generation, and JSON output.
- Packaged Linux binary was created and smoke-tested.

## Known Limitations

- Windows `.exe` must be built on Windows or a Windows build environment.
- Current success-path validation used one benign PE sample.
- Golden-vector parity testing against the old Anti_PE ((2)) extractor is recommended before production deployment.
- Scanner v1 reports `block` action in JSON but does not quarantine, delete, or directly block files.
- Final Agent integration may call the Python module or executable per event instead of using folder watch mode.

## Next Recommended Steps

- Run golden-vector parity tests with a small benign PE corpus.
- Build and smoke-test `anti_pe_scanner.exe` on Windows.
- Decide whether Agent integration will call the module, invoke the executable per file event, or use folder watch mode.
- Wire JSON `decision.action` into Agent enforcement policy if blocking/quarantine is desired.
- Add operational logging/telemetry conventions requested by the Agent team.
# Latency optimization handover

The scanner now supports a persistent JSONL worker and a single-read,
single-hash, single-LIEF-parse pipeline. The default event contract, model,
feature order, feature count, and thresholds are unchanged.

Build both Windows packages:

```powershell
.venv\Scripts\python.exe tools\build_exe.py --variant both
```

Outputs:

```text
dist/onedir/anti_pe_scanner/   # preferred Agent integration package
dist/onefile/                  # portable/manual package
```

The model, configs, and docs remain beside each runtime. Use the onedir build
with `--server` for endpoint integration. The onefile executable must unpack
itself at cold start and is retained for portability, not lowest startup
latency.

Linux measurements and remaining Windows/Agent validation are documented in
`artifacts/latency/LATENCY_COMPARISON.md`.
