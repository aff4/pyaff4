#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""The `.opidx` golden fixture.

The fixture was written for 40 triples drawn from java.util.Random with
seed 0x0D1DE7. The same triples are regenerated here, so the object
index this package builds must serialize to the fixture's bytes, and an HDT loaded with the
fixture must answer ??O and ?PO exactly as a filter of the triples does.
"""

from __future__ import annotations

import unittest

from pyhdt2_cython.build import from_triples, write_opidx_sidecar
from pyhdt2_cython.hdt import Hdt
from tests import HDT_FIXTURES

GOLDEN = HDT_FIXTURES / "opidx-golden.opidx"
NS = "http://example.org/"


class JavaRandom:
    """java.util.Random equivalent: the 48-bit linear congruential generator and nextInt(bound)."""

    MULTIPLIER = 0x5DEECE66D
    MASK = (1 << 48) - 1

    def __init__(self, seed: int) -> None:
        self.seed = (seed ^ self.MULTIPLIER) & self.MASK

    def _next(self, bits: int) -> int:
        self.seed = (self.seed * self.MULTIPLIER + 0xB) & self.MASK
        return self.seed >> (48 - bits)

    def next_int(self, bound: int) -> int:
        if bound & -bound == bound:
            return (bound * self._next(31)) >> 31
        while True:
            u = self._next(31)
            r = u % bound
            # Java rejects u when u - r + (bound - 1) overflows a signed 32-bit int.
            if u - r + bound - 1 < 1 << 31:
                return r


def fixture_triples() -> list[tuple[str, str, str]]:
    """The Java golden-fixture test's triples: 40 distinct triples, in drawing order."""
    rng = JavaRandom(0x0D1DE7)
    triples: dict[tuple[str, str, str], None] = {}
    while len(triples) < 40:
        s = f"{NS}s{rng.next_int(8)}"
        p = f"{NS}p{rng.next_int(3)}"
        o = f"{NS}o{rng.next_int(12)}"
        triples.setdefault((s, p, o))
    return list(triples)


class JavaRandomTests(unittest.TestCase):
    def test_matches_java_util_random(self) -> None:
        # new Random(42): nextInt(10) x5 then nextInt(16) x3, as printed by a JVM.
        rng = JavaRandom(42)
        self.assertEqual([rng.next_int(10) for _ in range(5)], [0, 3, 8, 4, 0])
        self.assertEqual([rng.next_int(16) for _ in range(3)], [15, 4, 11])

    def test_first_fixture_triples_match_the_jvm(self) -> None:
        # (s, p, o) indexes of new Random(0x0D1DE7)'s first six draws, as printed by a JVM.
        drawn = [(5, 1, 3), (4, 0, 7), (7, 0, 7), (4, 0, 6), (0, 2, 5), (1, 0, 6)]
        expected = [(f"{NS}s{s}", f"{NS}p{p}", f"{NS}o{o}") for s, p, o in drawn]
        self.assertEqual(fixture_triples()[:6], expected)


class OpIndexGoldenFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.triples = fixture_triples()
        self.data = from_triples(self.triples)
        self.golden = GOLDEN.read_bytes()

    def test_built_object_index_serializes_to_the_golden_bytes(self) -> None:
        positions, first, max_object = Hdt(self.data).op_index_arrays()
        self.assertEqual(
            write_opidx_sidecar(positions, first, max_object),
            self.golden,
            "the .opidx serialization differs from the Java golden fixture",
        )

    def test_golden_sidecar_answers_object_queries(self) -> None:
        hdt = Hdt(self.data, self.golden)
        self.assertEqual(hdt.sidecar_status["opidx"], "used")
        for o_idx in range(12):
            o = f"{NS}o{o_idx}"
            self.assertEqual(
                set(hdt.triples_with_pattern(None, None, o)),
                {t for t in self.triples if t[2] == o},
                f"??O mismatch for {o}",
            )
            for p_idx in range(3):
                p = f"{NS}p{p_idx}"
                self.assertEqual(
                    set(hdt.triples_with_pattern(None, p, o)),
                    {t for t in self.triples if t[1] == p and t[2] == o},
                    f"?PO mismatch for {p} {o}",
                )


if __name__ == "__main__":
    unittest.main()
