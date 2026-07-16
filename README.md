# Anti-PE LightGBM Agent Scanner

This is a LightGBM-only Agent-side PE malware scanner.

The scanner input is either a single file path or a watch directory. The model input is the 2381 numerical PE feature vector extracted from the PE file.

This project is inference-only. It does not include training pipelines or research experiments.

Operating modes:

- single-file mode
- continuous watch mode
- persistent JSONL server mode (preferred for Agent integration)

Final scanner output will be JSON.

Python single-file mode:

```bash
PYTHONPATH=src .venv/bin/python tools/scan_file.py --file README.md --model-package models/lightgbm_pe_v1 --pretty
```

Python continuous watch mode:

```bash
PYTHONPATH=src .venv/bin/python tools/scan_file.py --watch-dir ./samples --model-package models/lightgbm_pe_v1 --recursive
```

Executable single-file mode:

```bash
dist/anti_pe_scanner --file "C:\path\to\sample.exe"
```

Executable continuous watch mode:

```bash
dist/anti_pe_scanner --watch-dir "C:\Users\Test\Downloads"
```

Persistent worker mode:

```bash
dist/onedir/anti_pe_scanner/anti_pe_scanner --server --cache-size 64
```

Send one compact JSON object per line on stdin. The worker returns one JSON
object per line on stdout and sends diagnostics only to stderr:

```json
{"request_id":"42","file_path":"C:\\path\\sample.exe","host_context":{},"sha256":null}
```

On Windows, the executable is expected to be `anti_pe_scanner.exe`. Build on Windows or in a Windows build environment to produce the Windows `.exe`.

The model package must stay beside the executable under `dist/models/lightgbm_pe_v1/`. Training data is not included.

Policy thresholds:

- `alert_threshold`: `0.6242529630641415`
- `block_threshold`: `0.9385114343804422`

Scanner v1 reports `block` decisions in JSON when policy mode is `block_enabled`, but it does not quarantine, delete, or directly block files. The Agent integration layer should enforce actions.

Build packaged scanner:

```bash
PYTHONPATH=src .venv/bin/python tools/build_exe.py --variant both
```

Build Windows executable on Windows:

```powershell
.venv\Scripts\python.exe tools\build_exe.py
```

Before production deployment, run golden-vector parity testing against the old Anti_PE ((2)) extractor on known benign PE files.
