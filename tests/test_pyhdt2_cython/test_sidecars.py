#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""`.opidx` sidecars: Java golden fixtures, fallback, and Python-written sidecars."""

from __future__ import annotations

import unittest

import numpy as np

from pyhdt2_cython import PyHdt
from pyhdt2_cython.build import from_triples, write_opidx_sidecar
from pyhdt2_cython.hdt import Hdt, read_opidx_sidecar
from tests import HDT_FIXTURES

# Written by the Java HDT writer.
GOLDEN_OPIDX = HDT_FIXTURES / "opidx-golden.opidx"
SYNTHETIC = HDT_FIXTURES / "synthetic.hdt"
BASE_TYPE = "http://example.org/vocab#BaseType"
BROADER = "http://example.org/vocab#broader"


def object_queries(hdt: Hdt) -> list[tuple[str, str, str]]:
    """The ??O and ?PO results, which are what the sidecar accelerates."""
    out = list(hdt.triples_with_pattern(None, None, BASE_TYPE))
    return out + list(hdt.triples_with_pattern(None, BROADER, BASE_TYPE))


def chain_triples(n: int) -> list[tuple[str, str, str]]:
    return [
        (f"http://ex.org/s{i}", f"http://ex.org/p{i % 7}", f"http://ex.org/o{(i * 31) % 97}")
        for i in range(n)
    ]


class GoldenSidecarTests(unittest.TestCase):
    def test_java_opidx_header_and_sections_decode(self) -> None:
        entries, max_object, seq, bitmap = read_opidx_sidecar(GOLDEN_OPIDX.read_bytes())
        self.assertEqual((entries, max_object, seq.entries), (40, 12, 40))
        self.assertEqual(int(bitmap.cum[-1]), 12, "one set bit per object")


class SidecarFallbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = SYNTHETIC.read_bytes()
        self.expected = object_queries(Hdt(self.data))
        self.assertTrue(self.expected, "fixture query must match something")

    def test_stale_opidx_is_ignored(self) -> None:
        stale = Hdt(self.data, GOLDEN_OPIDX.read_bytes())
        self.assertTrue(stale.sidecar_status["opidx"].startswith("ignored: stale"))
        self.assertEqual(object_queries(stale), self.expected)

    def test_corrupt_opidx_is_ignored(self) -> None:
        corrupt = bytearray(GOLDEN_OPIDX.read_bytes())
        corrupt[-1] ^= 0xFF
        bad = Hdt(self.data, bytes(corrupt))
        self.assertTrue(bad.sidecar_status["opidx"].startswith("ignored: "))
        self.assertEqual(object_queries(bad), self.expected)

    def test_garbage_opidx_is_ignored(self) -> None:
        bad = Hdt(self.data, b"\x00not an opidx")
        self.assertTrue(bad.sidecar_status["opidx"].startswith("ignored: "))
        self.assertEqual(object_queries(bad), self.expected)


class WrittenSidecarTests(unittest.TestCase):
    def test_written_opidx_is_used_and_matches_the_built_index(self) -> None:
        data = from_triples(chain_triples(2_000))
        base = Hdt(data)
        positions, first, max_object = base.op_index_arrays()
        opidx = write_opidx_sidecar(positions, first, max_object)

        loaded = Hdt(data, opidx)
        self.assertEqual(loaded.sidecar_status, {"opidx": "used"})
        self.assertTrue(np.array_equal(loaded.op_index_arrays()[0], positions))
        for o in ("http://ex.org/o0", "http://ex.org/o42"):
            self.assertEqual(
                list(loaded.triples_with_pattern(None, None, o)),
                list(base.triples_with_pattern(None, None, o)),
            )
            self.assertEqual(
                list(loaded.triples_with_pattern(None, "http://ex.org/p3", o)),
                list(base.triples_with_pattern(None, "http://ex.org/p3", o)),
            )

    def test_pyhdt_accepts_sidecar_bytes(self) -> None:
        data = from_triples(chain_triples(200))
        opidx = write_opidx_sidecar(*Hdt(data).op_index_arrays())
        hdt = PyHdt(data, opidx_bytes=opidx)
        self.assertEqual(hdt._hdt.sidecar_status, {"opidx": "used"})
        self.assertEqual(sum(1 for _ in hdt.triples()), 200)

    def test_empty_graph_opidx_round_trips(self) -> None:
        data = from_triples([])
        positions, first, max_object = Hdt(data).op_index_arrays()
        loaded = Hdt(data, write_opidx_sidecar(positions, first, max_object))
        self.assertEqual(loaded.sidecar_status["opidx"], "used")
        self.assertEqual(list(loaded.triples_with_pattern(None, None, "http://ex.org/o")), [])


class SidecarConsistencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = from_triples(chain_triples(600))
        self.base = Hdt(self.data)

    def test_opidx_with_wrong_object_count_is_ignored(self) -> None:
        positions, first, max_object = self.base.op_index_arrays()
        opidx = write_opidx_sidecar(positions, first, max_object + 1)
        loaded = Hdt(self.data, opidx)
        status = loaded.sidecar_status["opidx"]
        self.assertTrue(status.startswith("ignored: "), status)
        self.assertIn(f"{max_object} object run starts", status)
        self.assertIn(f"max_object={max_object + 1}", status)
        o = "http://ex.org/o42"
        self.assertEqual(
            list(loaded.triples_with_pattern(None, None, o)),
            list(self.base.triples_with_pattern(None, None, o)),
        )


if __name__ == "__main__":
    unittest.main()
