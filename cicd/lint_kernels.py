#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Report CPython API calls inside each compiled hot function of the Cython kernels.

A white `cython -a` line has none; this is the scriptable version, run in CI after
cicd/cross_build.py has generated pyhdt2_cython/_kernels.c.
"""

import re
import sys
from pathlib import Path

C = Path(__file__).resolve().parent.parent / "pyhdt2_cython" / "_kernels.c"
PY_API = re.compile(
    r"\b(PyNumber_\w+|__Pyx_PyNumber_\w+|PyObject_\w+|__Pyx_PyLong_From\w+|__Pyx_PyLong_As\w+|"
    r"PyLong_\w+|__Pyx_GetModuleGlobalName|__Pyx_PyObject_Call\w*)\("
)
# Allowed to touch Python objects: buffer growth and the object index's scratch allocation (cold),
# affix, whose per-result output is a Python list of (id, str) tuples by design, and
# sort_unique_triples, which reads its three column widths from a tuple once per call, outside
# the row loops.
ALLOWED = {
    "3Pfc__grow",
    "3Pfc__ensure",
    "3Pfc_affix",
    "_zeroed_i64",
    "_zeroed_packed",
    "sort_unique_triples",
}
FUNC = re.compile(r"^static [^\n;]*?\b__pyx_f_13pyhdt2_cython_8_kernels_(\w+)\(([^)]*)\) \{$", re.M)


def main() -> int:
    src = C.read_text()
    bad = 0
    for m in FUNC.finditer(src):
        name = m.group(1)
        end = src.find("\n}\n", m.end())
        body = src[m.end() : end]
        body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
        calls = PY_API.findall(body)
        flag = "OK " if not calls else ("ok*" if name in ALLOWED else "PY ")
        if calls and name not in ALLOWED:
            bad += 1
        print(f"{flag} {name:<22} {len(calls):3d} {sorted(set(calls))[:4] if calls else ''}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
