# Continuous Mode

Continuous watch mode will monitor a directory and submit candidate files to the same LightGBM-only inference scanner used by single-file mode.

The watch mode is inference-only and will emit JSON events.

Python watch command:

```bash
PYTHONPATH=src .venv/bin/python tools/scan_file.py --watch-dir ./samples --model-package models/lightgbm_pe_v1 --recursive
```

Executable watch command:

```bash
anti_pe_scanner.exe --watch-dir "C:\Users\Test\Downloads"
```

Watch mode scans created and modified files after their size stabilizes. It suppresses duplicate unchanged events and continues running after per-file errors. Stop it with Ctrl+C.

The executable must be distributed with `models/lightgbm_pe_v1/` beside it. It performs inference only and includes no training data.

Folder watch mode is a v1 operational adapter. For Agent production integration, the Agent may instead call the scanner module or executable for each Agent-provided file event.
