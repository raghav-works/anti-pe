"""Build a PyInstaller scanner package.

The executable is inference-only. The LightGBM model package is intentionally
kept beside the executable instead of embedded so it can be inspected or
replaced as an operational artifact.
"""

from __future__ import annotations

import platform
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = PROJECT_ROOT / "dist"
EXE_NAME = "anti_pe_scanner"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--variant", choices=("onefile", "onedir", "both"), default="both"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    variants = ("onefile", "onedir") if args.variant == "both" else (args.variant,)
    for variant in variants:
        _build_variant(variant)
    return 0


def _build_variant(variant: str) -> None:
    variant_dist = DIST_DIR / variant
    pyinstaller_cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        f"--{variant}",
        "--clean",
        "--distpath",
        str(variant_dist),
        "--workpath",
        str(PROJECT_ROOT / "build" / variant),
        "--specpath",
        str(PROJECT_ROOT / "build" / variant),
        "--name",
        EXE_NAME,
        "--paths",
        str(PROJECT_ROOT / "src"),
        "--paths",
        str(PROJECT_ROOT / "tools"),
        str(PROJECT_ROOT / "tools" / "scan_file.py"),
    ]

    print("Running:", " ".join(pyinstaller_cmd))
    subprocess.run(pyinstaller_cmd, cwd=PROJECT_ROOT, check=True)

    binary_name = f"{EXE_NAME}.exe" if platform.system() == "Windows" else EXE_NAME
    runtime_root = variant_dist if variant == "onefile" else variant_dist / EXE_NAME
    _copy_tree(PROJECT_ROOT / "models", runtime_root / "models")
    _copy_tree(PROJECT_ROOT / "configs", runtime_root / "configs")
    _copy_tree(PROJECT_ROOT / "docs", runtime_root / "docs")
    binary_path = runtime_root / binary_name
    if not binary_path.exists():
        raise FileNotFoundError(f"Expected PyInstaller output was not created: {binary_path}")

    print(f"Created executable: {binary_path}")
    if platform.system() != "Windows":
        print("Note: this host produced a Linux binary. Build on Windows for anti_pe_scanner.exe.")


def _copy_tree(source: Path, destination: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Required packaging source is missing: {source}")
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)


if __name__ == "__main__":
    raise SystemExit(main())
