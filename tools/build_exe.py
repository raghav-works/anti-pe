"""Build a PyInstaller scanner package.

The executable is inference-only. The LightGBM model package is intentionally
kept beside the executable instead of embedded so it can be inspected or
replaced as an operational artifact.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = PROJECT_ROOT / "dist"
EXE_NAME = "anti_pe_scanner"


def main() -> int:
    pyinstaller_cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--clean",
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

    _copy_tree(PROJECT_ROOT / "models", DIST_DIR / "models")
    _copy_tree(PROJECT_ROOT / "configs", DIST_DIR / "configs")
    _copy_tree(PROJECT_ROOT / "docs", DIST_DIR / "docs")

    binary_name = f"{EXE_NAME}.exe" if platform.system() == "Windows" else EXE_NAME
    binary_path = DIST_DIR / binary_name
    if not binary_path.exists():
        raise FileNotFoundError(f"Expected PyInstaller output was not created: {binary_path}")

    print(f"Created executable: {binary_path}")
    if platform.system() != "Windows":
        print("Note: this host produced a Linux binary. Build on Windows for anti_pe_scanner.exe.")
    return 0


def _copy_tree(source: Path, destination: Path) -> None:
    if not source.exists():
        raise FileNotFoundError(f"Required packaging source is missing: {source}")
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)


if __name__ == "__main__":
    raise SystemExit(main())
