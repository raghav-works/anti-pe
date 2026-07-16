#!/usr/bin/env python3
"""Stage-aware cold/warm latency and memory benchmark."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
from pathlib import Path
from time import perf_counter_ns
from typing import Any

import numpy as np

try:
    import resource
except ImportError:  # Windows
    resource = None  # type: ignore[assignment]

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from anti_pe_scanner.scanner import PEMalwareScanner  # noqa: E402
from anti_pe_scanner.utils import safe_json_dumps  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    parser.add_argument("--model-package", default="models/lightgbm_pe_v1")
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--cold-runs", type=int, default=3)
    parser.add_argument("--cache-size", type=int, default=0)
    parser.add_argument("--num-threads", type=int, default=1)
    parser.add_argument("--json-output")
    return parser.parse_args()


def stats(values: list[float]) -> dict[str, float | int]:
    array = np.asarray(values, dtype=np.float64)
    return {
        "runs": len(values),
        "min_ms": round(float(array.min()), 3),
        "mean_ms": round(float(array.mean()), 3),
        "p50_ms": round(float(np.percentile(array, 50)), 3),
        "p95_ms": round(float(np.percentile(array, 95)), 3),
        "p99_ms": round(float(np.percentile(array, 99)), 3),
        "max_ms": round(float(array.max()), 3),
        "stddev_ms": round(float(statistics.pstdev(values)), 3),
    }


def cpu_model() -> str | None:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or None


def cold_process_times(
    path: Path, model_package: Path, runs: int, num_threads: int
) -> list[float]:
    values = []
    command = [
        sys.executable,
        str(PROJECT_ROOT / "tools" / "scan_file.py"),
        "--file",
        str(path),
        "--model-package",
        str(model_package),
        "--num-threads",
        str(num_threads),
    ]
    env = {**os.environ, "PYTHONPATH": str(SRC_ROOT)}
    for _ in range(runs):
        start = perf_counter_ns()
        result = subprocess.run(command, capture_output=True, text=True, env=env)
        values.append((perf_counter_ns() - start) / 1_000_000.0)
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
        event = json.loads(result.stdout)
        if event.get("scan_status") != "success":
            raise RuntimeError(safe_json_dumps(event, pretty=True))
    return values


def peak_rss_mb() -> float:
    if resource is None:
        return 0.0
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports KiB; macOS reports bytes.
    return value / (1024.0 * 1024.0) if sys.platform == "darwin" else value / 1024.0


def main() -> int:
    args = parse_args()
    if min(args.runs, args.cold_runs) < 1 or args.warmup < 0:
        raise SystemExit("runs must be >= 1 and warmup must be >= 0")
    path = Path(args.file).resolve()
    model_package = Path(args.model_package).resolve()

    import lief
    import lightgbm

    parsed = lief.PE.parse(str(path))
    if parsed is None:
        raise SystemExit("Benchmark file is not parseable by LIEF")

    scanner = PEMalwareScanner(
        model_package,
        cache_size=args.cache_size,
        num_threads=None if args.num_threads == 0 else args.num_threads,
    )
    for _ in range(args.warmup):
        event = scanner.scan_file(path)
        if event["scan_status"] != "success":
            raise SystemExit(safe_json_dumps(event, pretty=True))

    stage_values: dict[str, list[float]] = {}
    memory_after_each_scan_mb: list[float] = []
    last_event: dict[str, Any] = {}
    for _ in range(args.runs):
        last_event, timings = scanner.scan_file_with_timings(path)
        for key, value in timings.items():
            if isinstance(value, bool) or key in {"model_load_ms", "policy_load_ms"}:
                continue
            stage_values.setdefault(key, []).append(float(value))
        memory_after_each_scan_mb.append(peak_rss_mb())

    start = perf_counter_ns()
    safe_json_dumps(last_event)
    json_ms = (perf_counter_ns() - start) / 1_000_000.0
    cold_values = cold_process_times(path, model_package, args.cold_runs, args.num_threads)

    metadata = scanner.model_package.metadata or {}
    report = {
        "benchmark_file": {
            "path": str(path),
            "name": path.name,
            "size_bytes": path.stat().st_size,
            "size_mb": round(path.stat().st_size / 1024 / 1024, 3),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "architecture": str(parsed.header.machine),
            "sections": len(parsed.sections),
            "lief_parse_status": "success",
        },
        "environment": {
            "scanner_version": "0.1.0",
            "model_version": metadata.get("model_version"),
            "feature_version": metadata.get("feature_version"),
            "python_version": platform.python_version(),
            "lief_version": lief.__version__,
            "lightgbm_version": lightgbm.__version__,
            "numpy_version": np.__version__,
            "operating_system": platform.platform(),
            "cpu_model": cpu_model(),
            "lightgbm_num_threads": args.num_threads,
        },
        "warmup_runs_excluded": args.warmup,
        "cold_process_end_to_end": stats(cold_values),
        "warm_stages": {
            name: stats(values) for name, values in sorted(stage_values.items())
        },
        "json_serialization_single_ms": round(json_ms, 3),
        "memory": {
            "peak_process_memory_mb": round(max(memory_after_each_scan_mb), 3),
            "memory_after_each_scan_mb": [
                round(value, 3) for value in memory_after_each_scan_mb
            ],
            "peak_growth_first_to_last_mb": round(
                memory_after_each_scan_mb[-1] - memory_after_each_scan_mb[0], 3
            ),
            "note": (
                "ru_maxrss is a high-water mark, not instantaneous RSS."
                if resource is not None
                else "Peak RSS is unavailable without a Windows process-memory provider."
            ),
        },
        "last_scan": {
            "scan_status": last_event.get("scan_status"),
            "score": (last_event.get("model") or {}).get("score"),
            "verdict": (last_event.get("decision") or {}).get("verdict"),
        },
    }
    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if args.json_output:
        output = Path(args.json_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
