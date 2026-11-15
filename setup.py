#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Compile the Cython kernels against the stable ABI (abi3, CPython 3.12+).

Used for source installs (sdist, editable). Release wheels are cross-built with zig by
cicd/cross_build.py and packaged by cicd/build_wheels.py.
"""

import platform

from Cython.Build import cythonize
from setuptools import Extension, setup

LIMITED_API = "0x030C0000"
# Cython's own utility code (__Pyx__PyUnicode_EqualsUCS4) has a branch clang proves unreachable on
# CPython 3.12; the kernels themselves compile without this warning.
WARNING_FLAGS = ["-Wno-unreachable-code"]
CPU_FLAGS = ["-mpopcnt"] if platform.machine() in ("x86_64", "AMD64") else []

setup(
    ext_modules=cythonize(
        [
            Extension(
                "pyhdt2_cython._kernels",
                ["pyhdt2_cython/_kernels.py"],
                extra_compile_args=["-O3", *CPU_FLAGS, *WARNING_FLAGS],
                define_macros=[("Py_LIMITED_API", LIMITED_API)],
                py_limited_api=True,
            )
        ],
        compiler_directives={"language_level": 3},
    ),
    options={"bdist_wheel": {"py_limited_api": "cp312"}},
)
