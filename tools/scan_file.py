"""Command-line entry point for single-file scanning."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
RUNTIME_ROOT = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else PROJECT_ROOT
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from anti_pe_scanner.scanner import PEMalwareScanner  # noqa: E402
from anti_pe_scanner.server import run_jsonl_server  # noqa: E402
from anti_pe_scanner.utils import safe_json_dumps  # noqa: E402

try:
    from watch_dir import run_watch_dir  # noqa: E402
except ImportError:
    from tools.watch_dir import run_watch_dir  # type: ignore  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan one file with the LightGBM PE scanner.")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--file", help="File path to scan once.")
    target.add_argument("--watch-dir", help="Directory to monitor continuously.")
    target.add_argument("--server", action="store_true", help="Run persistent JSONL worker.")
    parser.add_argument(
        "--model-package",
        default="models/lightgbm_pe_v1",
        help="Path to the LightGBM model package.",
    )
    parser.add_argument("--policy", default=None, help="Optional policy JSON path.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    parser.add_argument("--recursive", action="store_true", help="Watch directories recursively.")
    parser.add_argument("--cache-size", type=int, default=0, help="Successful-result LRU entries.")
    parser.add_argument(
        "--num-threads",
        type=int,
        default=1,
        help="LightGBM threads for single-row prediction; use 0 for library default.",
    )
    return parser.parse_args(argv)


def resolve_runtime_path(path_value: str | None) -> str | None:
    if path_value is None:
        return None
    path = Path(path_value)
    if path.is_absolute():
        return str(path)
    runtime_candidate = RUNTIME_ROOT / path
    if runtime_candidate.exists():
        return str(runtime_candidate)
    return str(path)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        scanner = PEMalwareScanner(
            resolve_runtime_path(args.model_package),
            policy_path=resolve_runtime_path(args.policy),
            cache_size=args.cache_size,
            num_threads=None if args.num_threads == 0 else args.num_threads,
        )
    except Exception as exc:
        print(f"Scanner setup failed: {exc}", file=sys.stderr)
        return 2

    if args.file:
        event = scanner.scan_file(args.file)
        print(safe_json_dumps(event, pretty=args.pretty))
        return 0

    if args.server:
        return run_jsonl_server(scanner, sys.stdin, sys.stdout, sys.stderr)

    run_watch_dir(args.watch_dir, scanner=scanner, recursive=args.recursive, pretty=args.pretty)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
