# How To Run

This project is a LightGBM-only Agent-side PE malware scanner.

The scanner will accept either a single file path or a watch directory. Single-file mode is intended for direct on-demand scanning, while continuous watch mode is intended for monitoring a directory and scanning newly observed files.

The model input is a 2381-dimensional numerical PE feature vector extracted from a Windows PE file. This project is inference-only and does not include training workflows.

Final scan output will be JSON.

## Python Usage

Single-file mode:

```bash
PYTHONPATH=src .venv/bin/python tools/scan_file.py --file README.md --model-package models/lightgbm_pe_v1 --pretty
```

Continuous watch mode:

```bash
PYTHONPATH=src .venv/bin/python tools/scan_file.py --watch-dir ./samples --model-package models/lightgbm_pe_v1 --recursive
```

Stop watch mode with Ctrl+C.

## Executable Usage

Single-file mode:

```bash
anti_pe_scanner.exe --file "C:\path\to\sample.exe"
```

Continuous watch mode:

```bash
anti_pe_scanner.exe --watch-dir "C:\Users\Test\Downloads"
```

On Linux, PyInstaller creates `anti_pe_scanner` instead of `anti_pe_scanner.exe`. Build on Windows or in a Windows build environment for the Windows executable.

The executable performs inference only. Keep `models/lightgbm_pe_v1/` beside the executable. Training data is not included.

The scanner never scores raw files directly. It validates the file as a Windows PE, extracts the 2381 numerical features, and then calls the LightGBM model. Non-PE files are skipped with structured JSON.

Scanner v1 does not quarantine, delete, or directly block files. It reports the intended action in JSON for the Agent layer.
