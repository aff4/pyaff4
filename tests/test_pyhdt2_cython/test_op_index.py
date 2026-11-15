#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""The object index kernel, K.assemble_op_index (four object batches), against a plain sort."""

from __future__ import annotations

import random
import unittest

import numpy as np

from pyhdt2_cython import _kernels as K
from pyhdt2_cython.build import from_triples
from pyhdt2_cython.hdt import Hdt


def random_triples(seed: int, n: int, subjects: int, predicates: int, objects: int):
    rng = random.Random(seed)
    return {
        (
            f"http://ex.org/s{rng.randrange(subjects)}",
            f"http://ex.org/p{rng.randrange(predicates)}",
            f"http://ex.org/o{rng.randrange(objects)}",
        )
        for _ in range(n)
    }


def expected_op_index(hdt: Hdt) -> tuple[list[int], list[bool]]:
    """Each triple's Y position, sorted by (object, predicate, Y position), and run-start flags."""
    z_bits = np.unpackbits(np.frombuffer(hdt.bitmap_z.data, dtype=np.uint8), bitorder="little")
    group = np.concatenate(([0], np.cumsum(z_bits[: hdt.z.entries - 1]))).astype(int)
    rows = sorted(
        (hdt.z.get(z), hdt.y.get(int(y)), int(y)) for z, y in enumerate(group[: hdt.z.entries])
    )
    return [y for _, _, y in rows], [
        i == 0 or rows[i - 1][0] != o for i, (o, _, _) in enumerate(rows)
    ]


class AssembleOpIndexTests(unittest.TestCase):
    def assert_matches_sort(self, triples) -> None:
        hdt = Hdt(from_triples(sorted(triples)))
        positions, first, max_object = hdt.op_index_arrays()
        expected_positions, expected_first = expected_op_index(hdt)
        self.assertEqual(positions.tolist(), expected_positions)
        self.assertEqual(first.tolist(), expected_first)
        self.assertEqual(max_object, K.scan_max_object(hdt.index))

    def test_random_graphs_match_a_sort_by_object_predicate_position(self) -> None:
        shapes = [(1, 1, 1), (50, 3, 2), (20, 40, 5), (5, 2, 300), (200, 30, 60)]
        for seed, (subjects, predicates, objects) in enumerate(shapes):
            with self.subTest(subjects=subjects, predicates=predicates, objects=objects):
                self.assert_matches_sort(random_triples(seed, 1_500, subjects, predicates, objects))

    def test_single_triple(self) -> None:
        self.assert_matches_sort({("http://ex.org/s", "http://ex.org/p", "http://ex.org/o")})

    def test_one_object_holding_most_triples_leaves_batches_empty(self) -> None:
        hot = {(f"http://ex.org/s{i}", "http://ex.org/p", "http://ex.org/hot") for i in range(900)}
        self.assert_matches_sort(hot | random_triples(11, 100, 30, 5, 40))

    def test_empty_graph(self) -> None:
        hdt = Hdt(from_triples([]))
        start = np.zeros(K.scan_max_object(hdt.index) + 2, dtype=np.int64)
        K.assemble_op_index(hdt.index, memoryview(start), memoryview(bytearray(0)), 1)
        self.assertEqual(start.tolist(), [0, 0])


class AssembleOpIndexErrorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.hdt = Hdt(from_triples(sorted(random_triples(7, 300, 30, 4, 20))))
        self.n = self.hdt.z.entries
        self.bits = max(1, self.hdt.y.entries.bit_length())
        self.max_object = K.scan_max_object(self.hdt.index)

    def assemble(self, index, start_len: int, positions_len: int) -> None:
        start = np.zeros(start_len, dtype=np.int64)
        positions = bytearray(positions_len)
        K.assemble_op_index(index, memoryview(start), memoryview(positions), self.bits)

    def test_short_start_is_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, r"start holds \d+, needs \d+"):
            self.assemble(self.hdt.index, self.max_object + 1, (self.n * self.bits + 7) // 8)

    def test_short_positions_are_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, r"positions \(bytes\)"):
            self.assemble(self.hdt.index, self.max_object + 2, (self.n * self.bits + 7) // 8 - 1)

    def test_bitmap_z_marking_more_groups_than_y_is_refused(self) -> None:
        h = self.hdt
        sections = (h.shared, h.subjects, h.predicates, h.objects)
        short_y = K.TripleIndex(
            tuple(section.pfc for section in sections),
            tuple(section.num_strings for section in sections),
            h.objects.suffix_coded,
            (h.bitmap_y.data, h.bitmap_y.cum),
            (h.bitmap_z.data, h.bitmap_z.cum),
            (h.y.data, h.y.bits, h.y.entries - 1),
            (h.z.data, h.z.bits, h.z.entries),
        )
        with self.assertRaisesRegex(ValueError, "bitmap Z marks more than"):
            self.assemble(short_y, self.max_object + 2, (self.n * self.bits + 7) // 8)


if __name__ == "__main__":
    unittest.main()
