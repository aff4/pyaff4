#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Cross-compile the Cython kernels for six targets with zig and statically verify each binary.

    python cicd/cross_build.py [--target NAME ...]

`--target` (repeatable) builds only the named targets (keys of TARGETS); the default is all six.

Builds against CPython's stable ABI (Py_LIMITED_API = 3.12, the package's minimum Python). Outputs
go to build/cross/<target>/pyhdt2_cython/. Headers: the build interpreter's CPython 3.12 headers
for the Unix targets; for Windows, a copy of them with CPython's official PC/pyconfig.h
(`cross/pyconfig-windows.h`, checked against PYCONFIG_WINDOWS_SHA256). Windows links against an
import library generated from `cross/python3.def` (the python3.dll stable-ABI export list).
"""

import argparse
import hashlib
import platform
import re
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

HERE = Path(__file__).resolve().parent
PKG = HERE.parent
KERNELS_PY = PKG / "pyhdt2_cython" / "_kernels.py"
OUT = PKG / "build" / "cross"
LIMITED_API = "0x030C0000"
# python3.dll stable-ABI export list, copied from PyO3's python3-dll-a 0.2.14 crate (MIT licence).
PYTHON3_DEF = HERE / "cross" / "python3.def"
# CPython v3.12.15 PC/pyconfig.h, unmodified.
PYCONFIG_WINDOWS = HERE / "cross" / "pyconfig-windows.h"
PYCONFIG_WINDOWS_SHA256 = "0d0cfe802715933db0b8a889a99788906b82d75201e462a941705d2ea81395cd"
GLIBC_MAX = (2, 17)  # manylinux2014

TARGETS = {
    "linux-x86_64": {
        "zig": "x86_64-linux-gnu.2.17",
        "ext": ".abi3.so",
        "cflags": ["-fPIC", "-mcpu=x86_64_v2"],
    },
    "linux-aarch64": {"zig": "aarch64-linux-gnu.2.17", "ext": ".abi3.so", "cflags": ["-fPIC"]},
    "macos-x86_64": {
        "zig": "x86_64-macos.11.0",
        "ext": ".abi3.so",
        "cflags": ["-mcpu=x86_64_v2"],
        "ldflags": ["-Wl,-undefined,dynamic_lookup"],
    },
    "macos-arm64": {
        "zig": "aarch64-macos.11.0",
        "ext": ".abi3.so",
        "cflags": [],
        "ldflags": ["-Wl,-undefined,dynamic_lookup"],
    },
    "windows-x86_64": {
        "zig": "x86_64-windows-gnu",
        "ext": ".pyd",
        "cflags": ["-mcpu=x86_64_v2"],
        "implib": "i386:x86-64",
    },
    "windows-arm64": {
        "zig": "aarch64-windows-gnu",
        "ext": ".pyd",
        "cflags": [],
        "implib": "arm64",
    },
}


def zig(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "ziglang", *args], cwd=PKG, capture_output=True, text=True
    )


def cythonize() -> Path:
    from Cython.Build import cythonize as cy

    cy(
        [str(KERNELS_PY)],
        compiler_directives={"language_level": 3},
        force=True,
        quiet=True,
    )
    return KERNELS_PY.with_suffix(".c")


def windows_include() -> Path:
    if not PYCONFIG_WINDOWS.exists():
        raise SystemExit(
            f"{PYCONFIG_WINDOWS} is missing; add CPython v3.12.15's PC/pyconfig.h there, unmodified"
        )
    digest = hashlib.sha256(PYCONFIG_WINDOWS.read_bytes()).hexdigest()
    if digest != PYCONFIG_WINDOWS_SHA256:
        raise SystemExit(
            f"{PYCONFIG_WINDOWS} has sha256 {digest}, expected {PYCONFIG_WINDOWS_SHA256}; "
            "restore the unmodified CPython file or update the pin deliberately"
        )
    inc = OUT / "include-windows"
    if inc.exists():
        shutil.rmtree(inc)
    shutil.copytree(sysconfig.get_paths()["include"], inc)
    shutil.copy2(PYCONFIG_WINDOWS, inc / "pyconfig.h")
    return inc


def build(name: str, spec: dict, src: Path, win_inc: Path | None) -> tuple[Path | None, str]:
    out_dir = OUT / name / "pyhdt2_cython"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"_kernels{spec['ext']}"
    inc = win_inc if "implib" in spec else Path(sysconfig.get_paths()["include"])
    args = [
        "cc",
        "-target",
        spec["zig"],
        "-shared",
        "-O3",
        "-fno-strict-aliasing",
        "-Wno-unreachable-code",
        f"-DPy_LIMITED_API={LIMITED_API}",
        f"-I{inc}",
        *spec["cflags"],
        str(src),
        "-o",
        str(out),
        *spec.get("ldflags", []),
    ]
    if "implib" in spec:
        lib = OUT / name / "libpython3.a"
        res = zig("dlltool", "-d", str(PYTHON3_DEF), "-l", str(lib), "-m", spec["implib"])
        if res.returncode != 0:
            return None, f"dlltool failed: {res.stderr.strip()[-400:]}"
        args.append(str(lib))
    res = zig(*args)
    log = (res.stdout + res.stderr).strip()
    if res.returncode != 0:
        return None, log[-1500:]
    return out, log


def verify_elf(path: Path) -> list[str]:
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.elffile import ELFFile
    from elftools.elf.gnuversions import GNUVerNeedSection

    fails = []
    with path.open("rb") as f:
        elf = ELFFile(f)
        print(f"    format: ELF {elf.elfclass}-bit {elf['e_machine']}")
        syms = list(elf.get_section_by_name(".dynsym").iter_symbols())
        exported = {
            s.name
            for s in syms
            if s["st_shndx"] != "SHN_UNDEF" and s["st_info"]["bind"] == "STB_GLOBAL"
        }
        needed, versions = [], set()
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                needed += [t.needed for t in sec.iter_tags() if t.entry.d_tag == "DT_NEEDED"]
            if isinstance(sec, GNUVerNeedSection):
                for _, auxes in sec.iter_versions():
                    versions |= {a.name for a in auxes}
    glibc = sorted(
        tuple(map(int, v[len("GLIBC_") :].split("."))) for v in versions if v.startswith("GLIBC_")
    )
    newest = ".".join(map(str, glibc[-1])) if glibc else "none"
    print(
        f"    newest GLIBC symbol version: {newest} (manylinux2014 allows <= 2.17); NEEDED {needed}"
    )
    if "PyInit__kernels" not in exported:
        fails.append("PyInit__kernels not exported")
    if glibc and glibc[-1][:2] > GLIBC_MAX:
        fails.append(f"needs GLIBC {newest}")
    if any("python" in n for n in needed):
        fails.append("links libpython")
    return fails


def verify_macho(path: Path) -> list[str]:
    from macholib import mach_o
    from macholib.MachO import MachO
    from macholib.SymbolTable import SymbolTable

    fails = []
    macho = MachO(str(path))
    header = macho.headers[0]
    cpu = mach_o.CPU_TYPE_NAMES.get(header.header.cputype, header.header.cputype)
    minos, dylibs = None, []
    for lc, cmd, data in header.commands:
        if lc.cmd == mach_o.LC_BUILD_VERSION:
            minos = f"{cmd.minos >> 16}.{(cmd.minos >> 8) & 0xFF}"
        elif lc.cmd in (mach_o.LC_LOAD_DYLIB, mach_o.LC_LOAD_WEAK_DYLIB, mach_o.LC_REEXPORT_DYLIB):
            dylibs.append(data.rstrip(b"\0").decode())
    exported = {name.decode() for _, name in SymbolTable(macho).extdefsyms}
    print(f"    format: Mach-O {cpu}; minos: {minos}; dylibs: {dylibs}")
    if "_PyInit__kernels" not in exported:
        fails.append("PyInit__kernels not exported")
    if any("Python" in d or "libpython" in d for d in dylibs):
        fails.append("links libpython")
    if minos is None:
        fails.append("no LC_BUILD_VERSION (minimum macOS unknown)")
    return fails


def verify_pe(path: Path) -> list[str]:
    import pefile

    fails = []
    pe = pefile.PE(str(path))
    machine = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
    dlls = [e.dll.decode() for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
    exports = (
        [e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT")
        else []
    )
    print(f"    format: PE {machine}; imports: {dlls}")
    if "python3.dll" not in [d.lower() for d in dlls]:
        fails.append("does not import python3.dll (stable ABI)")
    if any(re.fullmatch(r"python3\d+\.dll", d.lower()) for d in dlls):
        fails.append("imports a version-specific python3XY.dll")
    if "PyInit__kernels" not in exports:
        fails.append("PyInit__kernels not exported")
    return fails


def verify(name: str, path: Path) -> list[str]:
    """Static checks via pure-Python parsers; returns failures (empty = pass)."""
    if name.startswith("linux"):
        return verify_elf(path)
    if name.startswith("macos"):
        return verify_macho(path)
    return verify_pe(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", action="append", choices=TARGETS, dest="targets")
    targets = parser.parse_args().targets or list(TARGETS)
    zig_version = zig("version").stdout.strip()
    print(f"zig {zig_version}; Py_LIMITED_API={LIMITED_API}; python {platform.python_version()}")
    src = cythonize()
    needs_windows = any("implib" in TARGETS[name] for name in targets)
    win_inc = windows_include() if needs_windows else None
    results = {}
    for name in targets:
        spec = TARGETS[name]
        print(f"== {name} ({spec['zig']})")
        path, log = build(name, spec, src, win_inc)
        if path is None:
            print("    BUILD FAILED:\n      " + log.replace("\n", "\n      "))
            results[name] = "build failed"
            continue
        warnings = [line for line in log.splitlines() if "warning" in line]
        size_kib = path.stat().st_size // 1024
        print(f"    built {path.relative_to(PKG)} ({size_kib} KiB), {len(warnings)} warnings")
        for line in warnings:
            print(f"      {line}")
        fails = verify(name, path) + ([f"{len(warnings)} compiler warnings"] if warnings else [])
        results[name] = "ok" if not fails else "; ".join(fails)
        print(f"    static checks: {results[name]}")
    print("summary:")
    for name, status in results.items():
        print(f"  {name:16} {status}")
    return 0 if all(status == "ok" for status in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
