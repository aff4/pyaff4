#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Every triple pattern against a brute-force filter of the full scan, on real HDT files."""

from __future__ import annotations

import random
import unittest

from pyhdt2_cython import PyHdt
from pyhdt2_cython.build import from_triples, write_opidx_sidecar
from pyhdt2_cython.hdt import Hdt
from tests import HDT_GRAPHS


def as_tuples(triples) -> list[tuple[str, str, str]]:
    return [(t.subject, t.predicate, t.object) for t in triples]


class PatternTests(unittest.TestCase):
    def assert_patterns_match_scan(self, hdt: PyHdt, samples: int = 300) -> None:
        scan = as_tuples(hdt.triples())
        rng = random.Random(7)
        picks = scan if len(scan) <= samples else rng.sample(scan, samples)
        for s, p, o in picks:
            cases = {
                (s, p, None): [t for t in scan if t[0] == s and t[1] == p],
                (s, None, o): [t for t in scan if t[0] == s and t[2] == o],
                (None, p, None): [t for t in scan if t[1] == p],
                (None, None, o): [t for t in scan if t[2] == o],
                (None, p, o): [t for t in scan if t[1] == p and t[2] == o],
            }
            for pattern, want in cases.items():
                got = as_tuples(hdt.triples_with_pattern(*pattern))
                # Distinct triples: a file may hold two dictionary entries that decode to the
                # same string (datatype-variants.hdt does), and a lookup by string finds one.
                self.assertEqual(sorted(set(got)), sorted(set(want)), pattern)
        self.assertEqual(list(hdt.triples_with_pattern(None, "http://absent/p", None)), [])
        self.assertEqual(list(hdt.triples_with_pattern(None, None, "http://absent/o")), [])

    def test_fixture_files(self) -> None:
        for path in HDT_GRAPHS:
            with self.subTest(file=path.name):
                self.assert_patterns_match_scan(PyHdt(path.read_bytes()))

    def test_same_results_with_written_sidecars(self) -> None:
        triples = [
            (f"http://ex.org/s{i % 97}", f"http://ex.org/p{i % 7}", f"http://ex.org/o{i % 53}")
            for i in range(3000)
        ]
        data = from_triples(triples)
        base = Hdt(data)
        opidx = write_opidx_sidecar(*base.op_index_arrays())
        with_sidecars = PyHdt(data, opidx_bytes=opidx)
        self.assertEqual(with_sidecars._hdt.sidecar_status, {"opidx": "used"})
        self.assert_patterns_match_scan(with_sidecars)
        self.assertEqual(as_tuples(with_sidecars.triples()), as_tuples(PyHdt(data).triples()))

    def test_object_index_is_built_on_first_object_query(self) -> None:
        hdt = Hdt(from_triples([("http://s", "http://p", "http://o")]))
        self.assertIsNone(hdt._op_index)
        list(hdt.triples_with_pattern(None, "http://p", None))
        self.assertIsNone(hdt._op_index, "?P? scans Y, not the object index")
        self.assertEqual(
            list(hdt.triples_with_pattern(None, None, "http://o")),
            [("http://s", "http://p", "http://o")],
        )
        self.assertIsNotNone(hdt._op_index)


if __name__ == "__main__":
    unittest.main()
