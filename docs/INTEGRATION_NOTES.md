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
# Persistent Agent integration

No endpoint Agent repository is present in this workspace, so its current call
chain could not be inspected or changed. Do not infer that the Agent already
uses any particular mode. Confirm its behavior before deployment.

The preferred scanner-side call chain is:

```text
Agent initialization
→ start onedir anti_pe_scanner.exe --server
→ scanner loads policy and LightGBM once
→ Agent receives a completed-file event
→ Agent writes one JSONL request
→ scanner reads, hashes, validates, and LIEF-parses the content once
→ exact 2,381-feature extraction
→ warm single-row inference
→ JSONL response with the same request_id
→ worker stays alive
```

Use `anti_pe_scanner.server.ScannerWorkerClient` as a Python reference. A
production Agent should additionally:

1. serialize access to each worker or use a bounded worker pool;
2. apply its own response timeout/cancellation primitive;
3. restart the process after EOF/crash, then retry only according to Agent policy;
4. continuously drain stderr;
5. send paths only after writes are complete;
6. send SHA-256 only when it was calculated from the exact content at that path;
7. issue `{"command":"shutdown","request_id":"..."}` during clean shutdown.

The scanner verifies a supplied SHA-256 against the bytes it actually read.
Mismatch returns `read_error`; the supplied value is never used to bypass
reading or content validation.

Server stdout is JSONL only. Example response:

```json
{"event":{"event_type":"ml_pe_scan","scan_status":"success"},"request_id":"42"}
```

Malformed requests produce a protocol-level `invalid_request` response and do
not terminate the worker. Existing `--file` and `--watch-dir` modes remain
available.

Optional successful-result caching is enabled with `--cache-size N`. Cache
identity includes SHA-256, model/feature version, and active decision policy.
The default is zero (disabled).
