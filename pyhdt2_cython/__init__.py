#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""HDT (Header Dictionary Triples) reader and writer: Python + NumPy, hot loops compiled by Cython.

The public API is `PyHdt` (constructor with optional `.opidx`
sidecar bytes, `triples`, iteration, `len`, `triples_with_pattern`, `subjects_with_po`, the
three `*_with_affixes` methods, `from_triples`, `write`) and `PyStringTriple`.

In a source checkout, set PYHDT2_CYTHON_INTERPRETED=1 to run `_kernels.py` uncompiled even when a
compiled `_kernels` extension sits next to it.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

if os.environ.get("PYHDT2_CYTHON_INTERPRETED") and "pyhdt2_cython._kernels" not in sys.modules:
    _source = Path(__file__).with_name("_kernels.py")
    _spec = importlib.util.spec_from_file_location("pyhdt2_cython._kernels", _source)
    if _spec is None or _spec.loader is None or not _source.exists():
        raise ImportError(
            f"PYHDT2_CYTHON_INTERPRETED is set but {_source} is missing; compiled wheels ship "
            "without it. Unset the variable, or install the py312-none-any wheel."
        )
    _module = importlib.util.module_from_spec(_spec)
    sys.modules["pyhdt2_cython._kernels"] = _module
    _spec.loader.exec_module(_module)

from pyhdt2_cython import build  # noqa: E402 (the kernels switch above must run first)
from pyhdt2_cython._kernels import PyStringTriple  # noqa: E402
from pyhdt2_cython.hdt import Hdt  # noqa: E402

__all__ = ["PyHdt", "PyStringTriple"]

DEFAULT_BASE_IRI = "urn:hdt:in-memory"


class PyHdt:
    """An HDT graph. Raises ValueError for unreadable input."""

    def __init__(
        self,
        bytes: bytes,  # noqa: A002 (matches the PyO3 signature)
        opidx_bytes: bytes | None = None,
    ) -> None:
        self._data = bytes
        self._hdt = Hdt(bytes, opidx_bytes)

    def __iter__(self) -> Iterator[PyStringTriple]:
        return self._hdt.string_triples()

    def __len__(self) -> int:
        """The number of triples: the length of BitmapTriples' object sequence, one per triple."""
        return self._hdt.z.entries

    def triples(self) -> Iterator[PyStringTriple]:
        return self._hdt.string_triples()

    def triples_with_pattern(
        self, s: str | None, p: str | None, o: str | None
    ) -> Iterator[PyStringTriple]:
        return self._hdt.string_triples(s, p, o)

    def subjects_with_po(self, p: str, o: str) -> Iterator[str]:
        return self._hdt.subjects_with_po(p, o)

    def subjects_with_affixes(self, prefix: str, suffix: str | None = None) -> Iterator[str]:
        return iter(self._hdt.subjects_with_affixes(prefix, suffix))

    def predicates_with_affixes(self, prefix: str, suffix: str | None = None) -> Iterator[str]:
        return iter(self._hdt.predicates_with_affixes(prefix, suffix))

    def objects_with_affixes(self, prefix: str, suffix: str | None = None) -> Iterator[str]:
        return iter(self._hdt.objects_with_affixes(prefix, suffix))

    @staticmethod
    def from_triples(
        triples: Iterable[Iterable[str]],
        base_iri: str = DEFAULT_BASE_IRI,
        *,
        original_size: int | None = None,
        psfc: bool = True,
    ) -> PyHdt:
        """Build from (s, p, o) term strings. `original_size` is written as hdt:originalSize when
        given; `psfc=False` writes a plain dictionaryFour dictionary instead of
        dictionaryFourPsfc."""
        rows = [tuple(t) for t in triples]
        return PyHdt(build.from_triples(rows, base_iri, original_size=original_size, psfc=psfc))

    def write(self, path: str) -> None:
        """Serialize this HDT to `path`, overwriting any existing file."""
        try:
            Path(path).write_bytes(self._data)
        except OSError as e:
            raise ValueError(f"write {path}: {e}") from e
