#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Check which pyaff4 wheel an installer selects for each target platform.

    python cicd/wheel_select.py

For each (platform, Python) pair, `uv pip install --target` resolves `pyaff4` from
dist/ only, and the installed dist-info's WHEEL file shows which wheel won. Expected: the matching
abi3 wheel on the six built targets, the py312-none-any fallback elsewhere, and no install at
all below Python 3.12.
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DIST = HERE.parent / "dist"
CASES = [
    ("x86_64-manylinux_2_28", "3.12", "cp312-abi3-manylinux_2_17_x86_64"),
    ("aarch64-manylinux_2_28", "3.13", "cp312-abi3-manylinux_2_17_aarch64"),
    ("x86_64-apple-darwin", "3.12", "cp312-abi3-macosx_11_0_x86_64"),
    ("aarch64-apple-darwin", "3.14", "cp312-abi3-macosx_11_0_arm64"),
    ("x86_64-pc-windows-msvc", "3.12", "cp312-abi3-win_amd64"),
    ("aarch64-pc-windows-msvc", "3.13", "cp312-abi3-win_arm64"),
    ("x86_64-unknown-linux-musl", "3.12", "py312-none-any"),
    ("x86_64-unknown-linux-musl", "3.14", "py312-none-any"),
    ("x86_64-manylinux_2_28", "3.11", None),
]


def select(platform: str, version: str) -> tuple[str | None, str]:
    target = Path(tempfile.mkdtemp(prefix="wheelsel-"))
    try:
        cmd = [
            "uv",
            "pip",
            "install",
            "--python",
            sys.executable,
            "--target",
            str(target),
            "--python-platform",
            platform,
            "--python-version",
            version,
            "--no-index",
            "--find-links",
            str(DIST),
            "--no-deps",
            "--no-build",
            "--quiet",
            "pyaff4",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            return None, proc.stderr.strip().splitlines()[
                -1
            ] if proc.stderr.strip() else "install failed"
        wheel = next(target.glob("pyaff4-*.dist-info/WHEEL")).read_text()
        tags = [line.split(": ", 1)[1] for line in wheel.splitlines() if line.startswith("Tag: ")]
        kernels = sorted(p.name for p in (target / "pyhdt2_cython").glob("_kernels*"))
        return tags[0], f"kernels: {kernels}"
    finally:
        shutil.rmtree(target)


def main() -> int:
    bad = 0
    for platform, version, expected in CASES:
        tag, detail = select(platform, version)
        ok = tag == expected
        bad += not ok
        shown = tag or "not installed"
        print(f"{'OK ' if ok else 'BAD'} {platform:27} py{version}  -> {shown:38} {detail[:90]}")
    print("wheel selection:", "as expected" if not bad else f"{bad} unexpected")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
