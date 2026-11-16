#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Package pyaff4, rdflib_hdt_ng, pyhdt2_cython and the cross-built kernels as `pyaff4` wheels.

    python cicd/build_wheels.py [--target NAME ...]

Produces, in dist/:
  - one `cp312-abi3-<platform>` wheel per cross-built target (from cross_build.py's build/cross/),
    carrying the compiled `pyhdt2_cython._kernels` and no `_kernels.py` source. `--target`
    (repeatable) limits this to the named targets; the default is all six;
  - one `py312-none-any` fallback wheel carrying `_kernels.py`, which runs interpreted (about 100x
    slower on queries). The py312 tag (not py3) puts the 3.12 floor in the tag itself: installers
    that skip Requires-Python for local wheels (uv with --find-links did) would otherwise install it
    on 3.11.

Metadata, dependencies, extras and console scripts come from pyproject.toml, so every wheel carries
the same metadata as a source build. Every `.py` file of the three packages is included.
"""

import argparse
import base64
import hashlib
import sys
import tomllib
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PKG = HERE.parent
PACKAGES = ["pyaff4", "rdflib_hdt_ng", "pyhdt2_cython"]
KERNELS_PY = "pyhdt2_cython/_kernels.py"
CROSS = PKG / "build" / "cross"
DIST = PKG / "dist"
# Wheel platform tags for each cross_build.py target. The Linux binaries need glibc <= 2.17
# (checked by cross_build.py), so they qualify for manylinux2014 even though NumPy 2.5 itself
# needs manylinux_2_28.
PLATFORM_TAGS = {
    "linux-x86_64": "manylinux_2_17_x86_64.manylinux2014_x86_64",
    "linux-aarch64": "manylinux_2_17_aarch64.manylinux2014_aarch64",
    "macos-x86_64": "macosx_11_0_x86_64",
    "macos-arm64": "macosx_11_0_arm64",
    "windows-x86_64": "win_amd64",
    "windows-arm64": "win_arm64",
}
# Fixed timestamp so rebuilding the same sources gives identical wheels.
ZIP_DATE = (2026, 1, 1, 0, 0, 0)


def metadata(project: dict) -> str:
    extras = project.get("optional-dependencies", {})
    # Author-email may appear only once, so all authors share one field.
    authors = ", ".join(f"{a['name']} <{a['email']}>" for a in project["authors"])
    lines = [
        "Metadata-Version: 2.4",
        f"Name: {project['name']}",
        f"Version: {project['version']}",
        f"Summary: {project['description']}",
        *([f"Keywords: {','.join(project['keywords'])}"] if "keywords" in project else []),
        f"Author-email: {authors}",
        f"License-Expression: {project['license']}",
        *(f"License-File: {f}" for f in project["license-files"]),
        *(f"Classifier: {c}" for c in project["classifiers"]),
        *(f"Project-URL: {k}, {v}" for k, v in project.get("urls", {}).items()),
        f"Requires-Python: {project['requires-python']}",
        *(f"Requires-Dist: {d}" for d in project["dependencies"]),
        *(f"Provides-Extra: {extra}" for extra in extras),
        *(
            f"Requires-Dist: {d}; extra == '{extra}'"
            for extra, deps in extras.items()
            for d in deps
        ),
        "Description-Content-Type: text/markdown",
    ]
    readme = (PKG / project["readme"]).read_text()
    return "\n".join(lines) + "\n\n" + readme


def entry_points(project: dict) -> str:
    scripts = project.get("scripts", {})
    return "[console_scripts]\n" + "".join(f"{name} = {ref}\n" for name, ref in scripts.items())


def pure_modules() -> dict[str, bytes]:
    """Every .py file of the three packages, by archive name, except the kernels' source."""
    files = {}
    for package in PACKAGES:
        for path in sorted((PKG / package).rglob("*.py")):
            arcname = path.relative_to(PKG).as_posix()
            if arcname != KERNELS_PY:
                files[arcname] = path.read_bytes()
    return files


def record_line(arcname: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{arcname},sha256={digest},{len(data)}"


def write_wheel(project: dict, tag: str, files: dict[str, bytes], purelib: bool) -> Path:
    dist_name = project["name"].replace("-", "_")
    version = project["version"]
    py_tag, abi_tag, plat_tag = tag.split("-", 2)
    dist_info = f"{dist_name}-{version}.dist-info"
    wheel_meta = (
        "Wheel-Version: 1.0\n"
        "Generator: pyaff4 cicd/build_wheels.py\n"
        f"Root-Is-Purelib: {'true' if purelib else 'false'}\n"
        + "".join(f"Tag: {py_tag}-{abi_tag}-{p}\n" for p in plat_tag.split("."))
    )
    entries = {
        **files,
        **{f"{dist_info}/licenses/{f}": (PKG / f).read_bytes() for f in project["license-files"]},
        f"{dist_info}/METADATA": metadata(project).encode(),
        f"{dist_info}/WHEEL": wheel_meta.encode(),
        f"{dist_info}/entry_points.txt": entry_points(project).encode(),
    }
    record = [record_line(name, data) for name, data in entries.items()]
    record.append(f"{dist_info}/RECORD,,")
    entries[f"{dist_info}/RECORD"] = ("\n".join(record) + "\n").encode()
    path = DIST / f"{dist_name}-{version}-{tag}.whl"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, entries[name])
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", action="append", choices=PLATFORM_TAGS, dest="targets")
    targets = parser.parse_args().targets or list(PLATFORM_TAGS)
    project = tomllib.loads((PKG / "pyproject.toml").read_text())["project"]
    DIST.mkdir(exist_ok=True)
    for old in DIST.glob("*.whl"):
        old.unlink()
    pure = pure_modules()
    built = []
    for target in targets:
        pkg = CROSS / target / "pyhdt2_cython"
        kernels = next(iter([*pkg.glob("_kernels*.so"), *pkg.glob("_kernels*.pyd")]), None)
        if kernels is None:
            print(f"missing cross-built kernels for {target}; run cicd/cross_build.py first")
            return 1
        files = {**pure, f"pyhdt2_cython/{kernels.name}": kernels.read_bytes()}
        tag = f"cp312-abi3-{PLATFORM_TAGS[target]}"
        built.append(write_wheel(project, tag, files, purelib=False))
    fallback = {**pure, KERNELS_PY: (PKG / KERNELS_PY).read_bytes()}
    built.append(write_wheel(project, "py312-none-any", fallback, purelib=True))
    for path in built:
        print(f"{path.stat().st_size / 1024:7.0f} KiB  {path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
