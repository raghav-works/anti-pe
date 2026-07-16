# PE scanner latency investigation

## Scope and integration finding

No Agent repository is available in this workspace. Its actual dispatch,
concurrency, hashing, completed-write guarantee, duplicate behavior, and
event-to-verdict timing therefore remain unverified. Scanner-side integration
support is complete, but no Agent changes or Agent latency numbers are claimed.

Observed original scanner flow:

```text
CLI/watch event
→ start process when invoked with --file
→ load model and policy
→ stat + SHA-256 for event metadata
→ validator opens file and checks headers
→ validator asks LIEF to parse the path
→ extractor reopens and reads the complete file
→ bytes → list of one Python reference per byte
→ LIEF parses a second time
→ extract 2,381 features
→ LightGBM prediction
→ verdict + JSON
→ process exits in --file mode
```

Optimized flow:

```text
Agent starts onedir worker once
→ model and policy load once
→ JSONL completed-file request
→ stat and enforce 100 MiB policy
→ read once and verify stable stat
→ SHA-256 from those bytes
→ validate MZ/e_lfanew/PE signature from those bytes
→ LIEF parses those bytes once
→ exact 2,381-feature extraction
→ one-thread warm LightGBM prediction
→ JSONL response and flush
→ worker remains alive
```

## Root causes

1. `list(raw_bytes)` created roughly one Python reference for every byte.
2. Whole-file `np.bincount` caused an additional platform-integer promotion on
   large inputs.
3. Valid files were hashed twice, opened repeatedly, and parsed twice.
4. Entropy windows calculated two histograms over the same bytes.
5. String extraction built a second joined bytes object and repeatedly scanned it.
6. Default LightGBM threading was extremely slow for one row on this Linux host.
7. `--file` reloads Python/PyInstaller and the model for every invocation.
8. Watch mode still has a 0.5-second stability wait; an Agent that guarantees
   completed files should use server mode instead.

## Near-100 MB Linux benchmark

File: `vlc-3.0.23-win64-95mb-overlay.exe`; 99,614,720 bytes (95.000 MiB);
SHA-256 `6659ee55daaca8c5c0a175429d3ef65e06b310350b3333bfaee0765f75d874e8`;
LIEF parse successful; 7 sections; LIEF reports `MACHINE_TYPES.I386`.

Environment: Linux 6.17, Intel Core i9-14900, Python 3.12.3, LIEF
0.17.6, LightGBM 4.6.0, NumPy 2.5.1. Optimized results use 3 warm-ups
and 20 measured warm scans. The original repeated run used only 10 measured
scans because each scan retained a roughly 1.1 GiB high-water memory footprint.

| Near-100 MB PE metric | Original | Optimized | Improvement |
| --- | ---: | ---: | ---: |
| File size | 99,614,720 B | 99,614,720 B | unchanged |
| Cold process P50 | not comparably measured | 2,913.689 ms | pending Windows builds |
| Warm total P50 | 6,675.992 ms | 2,371.649 ms | 64.5% |
| Warm total P95 | 6,852.524 ms | 2,590.698 ms | 62.2% |
| Warm total P99 | 6,934.801 ms | 2,625.019 ms | 62.1% |
| File read P50 | not isolated | 30.695 ms | single read |
| SHA-256 P50 | not isolated | 43.694 ms | one hash |
| LIEF parse P50 | not isolated | 38.108 ms | one parse |
| Entropy extraction P50 | not isolated | 1,067.961 ms | reused byte counts |
| Complete feature extraction P50 | 7,166.538 ms (single run) | 2,259.155 ms | 68.5% |
| Model inference P50 | not isolated | 0.419 ms | one thread |
| Peak memory usage | 1,206,736 KiB | 407.074 MiB | about 65% lower |
| Agent event-to-verdict P50 | unavailable | unavailable | Agent repo absent |
| Agent event-to-verdict P95 | unavailable | unavailable | Agent repo absent |

The largest warm feature groups are byte entropy and strings, each around
1.0–1.1 seconds P50. Persistent JSONL round-trip across 20 requests measured
2,375.255 ms P50, 2,412.202 ms P95, and 2,534.576 ms P99. It removes repeated
model/process startup but cannot remove the content-dependent feature work.

LightGBM model-only test (500 predictions) produced the identical score:

| Threads | P50 | P95 |
| --- | ---: | ---: |
| library default | 25.7374 ms | 33.8020 ms |
| 1 | 0.0978 ms | 0.1471 ms |
| 2 | 0.0991 ms | 0.1246 ms |

One thread is the default because it had the lowest P50 and avoids default
thread-pool overhead. It remains configurable with `--num-threads`.

## Correctness and stability

- Original and optimized 95 MB vectors both had shape `(1, 2381)`.
- `np.array_equal` returned true: zero differing positions and maximum absolute
  difference `0.0`.
- Original and optimized scores were both `0.23047213546955497`.
- Verdict remained `allow`; status remained `success`.
- Across 20 persistent-process scans, the high-water mark increased only
  0.113 MiB from first to last, rather than continuously increasing.
- A failed JSONL request did not terminate the worker; the next request succeeded.
- The model is constructed once per worker.
- Exactly 100 MiB remained parseable and scanned successfully.
- 100 MiB + 1 byte returned `skipped_too_large` without LIEF parsing,
  feature extraction, or inference.

## Remaining required target validation

These cannot be honestly produced on the current Linux-only, scanner-only
workspace:

- actual Agent call-chain inspection and Agent source changes;
- Agent event-to-verdict measurements;
- Windows endpoint measurements;
- PyInstaller onefile versus onedir startup measurements;
- a newly built Windows executable/handover archive.

The Windows workflow now builds and uploads both variants. Run it on the
representative endpoint, execute the benchmark command below for each binary
mode, and add those measurements to this report:

```powershell
$env:PYTHONPATH = "src"
.venv\Scripts\python.exe tools\benchmark_latency.py `
  --file samples\large\vlc-3.0.23-win64-95mb-overlay.exe `
  --runs 20 --warmup 3 --cold-runs 3 `
  --json-output artifacts\latency\after\near_100mb_windows.json
```
