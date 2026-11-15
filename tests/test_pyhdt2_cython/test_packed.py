#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Packed sequences and bitmaps read in place: wide values, bounds, and no copies of the input."""

from __future__ import annotations

import random
import unittest

import numpy as np

from pyhdt2_cython import _kernels as K
from pyhdt2_cython.build import encode_bitmap, encode_sequence, from_triples
from pyhdt2_cython.hdt import Bitmap, Hdt, Sequence, _Reader


class PackedSequenceTests(unittest.TestCase):
    def test_values_wider_than_32_bits(self) -> None:
        rng = random.Random(3)
        for bits in (1, 7, 31, 32, 33, 40, 63, 64):
            with self.subTest(bits=bits):
                top = (1 << bits) - 1
                values = [0, top, 1, top - 1] + [rng.randint(0, top) for _ in range(500)]
                encoded = encode_sequence(np.array(values, dtype=np.uint64))
                seq = Sequence(_Reader(encoded))
                self.assertEqual(seq.bits, bits)
                self.assertEqual([seq.get(i) & ((1 << 64) - 1) for i in range(len(values))], values)
                self.assertEqual(seq.unpack().tolist(), values)

    def test_last_entry_reads_no_further_than_the_sequence(self) -> None:
        # 3 entries of 40 bits = 15 bytes: the last entry ends mid-word, with nothing after it.
        values = [2**40 - 1, 5, 2**39 + 3]
        encoded = encode_sequence(np.array(values, dtype=np.uint64))
        body = memoryview(bytes(Sequence(_Reader(encoded)).data))
        self.assertEqual(len(body), 15)
        self.assertEqual([K.seq_get(body, 40, i) for i in range(3)], values)

    def test_sequences_and_bitmaps_are_views_of_the_input(self) -> None:
        data = from_triples([(f"http://s{i}", "http://p", f"http://o{i}") for i in range(50)])
        hdt = Hdt(data)
        for name, view in (
            ("Y", hdt.y.data),
            ("Z", hdt.z.data),
            ("bitmap Y", hdt.bitmap_y.data),
            ("bitmap Z", hdt.bitmap_z.data),
        ):
            with self.subTest(name):
                self.assertIs(view.obj, data)


class InPlaceBitmapTests(unittest.TestCase):
    def test_rank_and_select_agree_with_brute_force(self) -> None:
        rng = random.Random(9)
        for n in (1, 63, 64, 65, 511, 512, 513, 5000):
            with self.subTest(n=n):
                bits = np.array([rng.random() < 0.3 for _ in range(n)], dtype=bool)
                bitmap = Bitmap.read(_Reader(encode_bitmap(bits)))
                ones = np.flatnonzero(bits)
                for i in range(n + 1):
                    self.assertEqual(bitmap.rank1(i), int(bits[:i].sum()))
                for k, pos in enumerate(ones):
                    self.assertEqual(bitmap.select1(k), pos)
                self.assertEqual(bitmap.select1(len(ones)), -1)


TRAILER = b"NEXT"


class SectionLengthTests(unittest.TestCase):
    """Each body is exactly ceil(bits / 8) bytes, so the reader stops at the next section."""

    def test_empty_bitmap_reads_no_body(self) -> None:
        r = _Reader(encode_bitmap(np.zeros(0, dtype=bool)) + TRAILER)
        bitmap = Bitmap.read(r)
        self.assertEqual(bitmap.num_bits, 0)
        self.assertEqual(bytes(r.take(len(TRAILER))), TRAILER)
        self.assertEqual(bitmap.rank1(0), 0)
        self.assertEqual(bitmap.select1(0), -1)

    def test_entries_are_at_least_one_bit_wide(self) -> None:
        for values in ([], [0], [0, 0, 0]):
            with self.subTest(values=values):
                seq = Sequence(_Reader(encode_sequence(np.array(values, dtype=np.uint64))))
                self.assertEqual((seq.bits, seq.entries), (1, len(values)))

    def test_empty_sequence_reads_no_body(self) -> None:
        encoded = encode_sequence(np.zeros(0, dtype=np.uint64))
        r = _Reader(encoded + TRAILER)
        self.assertEqual(Sequence(r).entries, 0)
        self.assertEqual(bytes(r.take(len(TRAILER))), TRAILER)

    def test_bitmap_bodies_around_word_boundaries(self) -> None:
        for n in (1, 7, 8, 9, 63, 64, 65, 127, 128, 129, 1000):
            with self.subTest(n=n):
                bits = np.arange(n) % 3 == 0
                r = _Reader(encode_bitmap(bits) + TRAILER)
                bitmap = Bitmap.read(r)
                self.assertEqual(len(bitmap.data), (n + 7) // 8)
                self.assertEqual(bytes(r.take(len(TRAILER))), TRAILER)

    def test_sequence_bodies_around_word_boundaries(self) -> None:
        sizes = ((1, 63), (1, 64), (1, 65), (7, 9), (13, 5), (64, 1), (64, 3), (33, 2))
        for bits, entries in sizes:
            with self.subTest(bits=bits, entries=entries):
                values = np.full(entries, (1 << bits) - 1, dtype=np.uint64)
                encoded = encode_sequence(values)
                r = _Reader(encoded + TRAILER)
                seq = Sequence(r)
                self.assertEqual(len(seq.data), (bits * entries + 7) // 8)
                self.assertEqual(bytes(r.take(len(TRAILER))), TRAILER)


if __name__ == "__main__":
    unittest.main()
