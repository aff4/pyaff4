#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""HDT generation: output matches the goldens, and the reorganise kernels on edge cases."""

from __future__ import annotations

import random
import unittest
from collections.abc import Sequence
from datetime import UTC, datetime
from unittest import mock

import numpy as np

from pyhdt2_cython import _kernels as K
from pyhdt2_cython.build import _pack_sorted, from_triples
from pyhdt2_cython.hdt import Hdt
from tests import HDT_FIXTURES

GOLDEN = HDT_FIXTURES / "build-golden"
XSD = "http://www.w3.org/2001/XMLSchema#"
EX = "http://ex.org/"


def _term_pool(rng: random.Random, n: int) -> list[str]:
    pieces = ["a", "b", "ab", "é", "ü", "\uffff", "\U00010000", "\U0001f600", "x/y", "z" * 20]
    out = []
    for i in range(n):
        tail = "".join(rng.choice(pieces) for _ in range(rng.randrange(0, 4)))
        out.append(f"{EX}{rng.choice(['r', 'res/', 'res/item'])}{tail}{i % 7}")
    return out


def _literals(rng: random.Random, n: int) -> list[str]:
    out = []
    for i in range(n):
        v = rng.choice(["v", "a\\\\b", 'w\\"x', "é", "\U00010000", "1", "^^"]) + str(i % 11)
        kind = rng.randrange(4)
        if kind == 0:
            out.append(f'"{v}"')
        elif kind == 1:
            out.append(f'"{v}"@{rng.choice(["en", "en-gb", "de"])}')
        elif kind == 2:
            out.append(f'"{v}"^^<{XSD}{rng.choice(["long", "dateTime", "hexBinary"])}>')
        else:
            out.append(f"_:b{i % 13}")
    return out


def random_graph(seed: int, n_triples: int, n_res: int, n_pred: int, n_lit: int):
    rng = random.Random(seed)
    res = _term_pool(rng, n_res)
    lits = _literals(rng, n_lit)
    preds = [f"{EX}p/{i}" for i in range(n_pred)]
    triples = []
    for _ in range(n_triples):
        s = rng.choice(res) if rng.random() < 0.9 else f"_:b{rng.randrange(13)}"
        o = rng.choice(res) if rng.random() < 0.5 else rng.choice(lits)
        triples.append((s, rng.choice(preds), o))
    return triples


def golden_cases() -> dict[str, list[tuple[str, str, str]]]:
    """The inputs of the goldens, which were written by the set-based builder that the
    reorganise pipeline replaced."""
    supplementary = [
        (f"{EX}\uffff", f"{EX}p", f"{EX}\U00010000"),
        (f"{EX}\U00010000", f"{EX}p", f"{EX}\uffff"),
        (f"{EX}\ue000", f"{EX}p", '"\U0001f600"'),
    ]
    all_shared = [(f"{EX}n{i}", f"{EX}p", f"{EX}n{(i + 1) % 40}") for i in range(40)]
    no_shared = [(f"{EX}s{i}", f"{EX}p{i % 3}", f'"o{i}"^^<{XSD}long>') for i in range(40)]
    duplicates = [(f"<{EX}s>", f"<{EX}p>", f"<{EX}o>")] * 3 + [(f"{EX}s", f"{EX}p", f"{EX}o")]
    return {
        "empty": [],
        "single": [(f"{EX}s", f"{EX}p", '"x"')],
        "supplementary": supplementary,
        "all_shared": all_shared,
        "no_shared": no_shared,
        "duplicates": duplicates,
        "random_small": random_graph(1, 300, 60, 5, 40),
        "random_medium": random_graph(2, 3000, 400, 17, 300),
    }


class SectionTypeTests(unittest.TestCase):
    def test_every_dictionary_section_is_length_prefixed(self) -> None:
        for name, triples in golden_cases().items():
            for psfc in (True, False):
                hdt = Hdt(from_triples(triples, psfc=psfc))
                sections = (hdt.shared, hdt.subjects, hdt.predicates, hdt.objects)
                with self.subTest(graph=name, psfc=psfc):
                    self.assertEqual([s.enc for s in sections], [K.ENC_LENGTH_PREFIXED] * 4)


class GoldenTests(unittest.TestCase):
    def setUp(self) -> None:
        issued = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
        self.enterContext(mock.patch("pyhdt2_cython.build._utc_now", return_value=issued))
        self.enterContext(mock.patch("pyhdt2_cython.build._software", return_value="pyaff4/golden"))

    def test_output_matches_the_goldens(self) -> None:
        for name, triples in golden_cases().items():
            for psfc in (True, False):
                with self.subTest(name=name, psfc=psfc):
                    golden = GOLDEN / f"{name}-{'psfc' if psfc else 'plain'}.hdt"
                    self.assertEqual(from_triples(triples, psfc=psfc), golden.read_bytes())

    def test_arrival_order_does_not_matter(self) -> None:
        triples = golden_cases()["random_small"]
        shuffled = list(triples)
        random.Random(5).shuffle(shuffled)
        self.assertEqual(from_triples(shuffled), from_triples(triples))


def intersect(a: list[bytes], b: list[bytes]) -> tuple[int, list[int], list[int]]:
    pa, pb = _pack_sorted(a), _pack_sorted(b)
    a_shared = np.zeros(len(a), dtype=np.int64)
    b_shared = np.zeros(len(b), dtype=np.int64)
    n = K.intersect_sorted(
        pa.data,
        memoryview(pa.offsets),
        pb.data,
        memoryview(pb.offsets),
        memoryview(a_shared),
        memoryview(b_shared),
    )
    return n, a_shared.tolist(), b_shared.tolist()


class IntersectTests(unittest.TestCase):
    def test_empty_and_disjoint_sides(self) -> None:
        self.assertEqual(intersect([], []), (0, [], []))
        self.assertEqual(intersect([b"a"], []), (0, [0], []))
        self.assertEqual(intersect([b"a", b"c"], [b"b", b"d"]), (0, [0, 0], [0, 0]))

    def test_shared_ids_count_up_in_order(self) -> None:
        a = [b"a", b"b", b"c", b"e"]
        b = [b"b", b"d", b"e"]
        self.assertEqual(intersect(a, b), (2, [0, 1, 0, 2], [1, 0, 2]))

    def test_a_prefix_is_not_a_match(self) -> None:
        self.assertEqual(intersect([b"a", b"ab"], [b"ab", b"abc"]), (1, [0, 1], [1, 0]))

    def test_terms_compare_as_utf8_bytes(self) -> None:
        # U+FFFF sorts before U+10000 in UTF-8 (and code points), after it in UTF-16.
        a = sorted(t.encode() for t in ("\uffff", "\U00010000"))
        self.assertEqual(intersect(a, [a[1]]), (1, [0, 1], [1]))

    def test_matches_a_set_intersection(self) -> None:
        rng = random.Random(11)
        for _ in range(50):
            a = sorted({bytes(rng.choices(b"ab\xc3\xa9", k=rng.randrange(4))) for _ in range(20)})
            b = sorted({bytes(rng.choices(b"ab\xc3\xa9", k=rng.randrange(4))) for _ in range(20)})
            common = sorted(set(a) & set(b))
            n, a_shared, b_shared = intersect(a, b)
            self.assertEqual(n, len(common))
            self.assertEqual([a[i] for i, k in enumerate(a_shared) if k], common)
            self.assertEqual([b[i] for i, k in enumerate(b_shared) if k], common)


def sort_unique(rows: Sequence[tuple[int, ...]], bits: tuple[int, int, int]):
    s, p, o = (np.array([r[k] for r in rows], dtype=np.uint64) for k in range(3))
    scratch = tuple(memoryview(np.empty(len(rows), dtype=np.uint64)) for _ in range(3))
    kept = K.sort_unique_triples(memoryview(s), memoryview(p), memoryview(o), scratch, bits)
    return list(zip(s[:kept].tolist(), p[:kept].tolist(), o[:kept].tolist(), strict=True))


class SortUniqueTriplesTests(unittest.TestCase):
    def test_small_inputs(self) -> None:
        self.assertEqual(sort_unique([], (0, 0, 0)), [])
        self.assertEqual(sort_unique([(1, 2, 3)], (1, 2, 2)), [(1, 2, 3)])
        self.assertEqual(
            sort_unique([(2, 1, 1), (1, 1, 1), (2, 1, 1)], (2, 1, 1)), [(1, 1, 1), (2, 1, 1)]
        )

    def test_matches_sorted_set_for_any_width(self) -> None:
        rng = random.Random(4)
        for bits in ((1, 1, 1), (3, 17, 5), (16, 16, 16), (17, 33, 40), (64, 2, 64)):
            with self.subTest(bits=bits):
                rows = [tuple(rng.getrandbits(b) for b in bits) for _ in range(2000)]
                rows += rows[:300]
                self.assertEqual(sort_unique(rows, bits), sorted(set(rows)))

    def test_zero_width_columns_are_skipped(self) -> None:
        rows = [(3, 0, 1), (1, 0, 2), (3, 0, 0)]
        self.assertEqual(sort_unique(rows, (2, 0, 2)), sorted(rows))

    def test_short_scratch_is_rejected(self) -> None:
        column = memoryview(np.zeros(3, dtype=np.uint64))
        scratch = tuple(memoryview(np.zeros(2, dtype=np.uint64)) for _ in range(3))
        with self.assertRaisesRegex(ValueError, "scratch"):
            K.sort_unique_triples(column, column, column, scratch, (1, 1, 1))


class PfcEncodeIdsTests(unittest.TestCase):
    def encode(self, terms: list[bytes], ids: list[int]) -> bytes:
        packed = _pack_sorted(terms)
        out = np.zeros(sum(map(len, terms)) * 2 + 8 * len(ids) + 1, dtype=np.uint8)
        block_offsets = np.zeros(len(ids) + 2, dtype=np.uint64)
        id_array = np.array(ids, dtype=np.int64)
        used = K.pfc_encode(
            packed.data,
            memoryview(packed.offsets),
            memoryview(id_array),
            16,
            memoryview(out),
            memoryview(block_offsets),
        )
        return out[:used].tobytes()

    def test_encodes_only_the_given_terms(self) -> None:
        terms = [b"a", b"ab", b"b", b"bc"]
        # "ab" whole (length 2), then "bc" sharing nothing (0) and adding 2 bytes.
        self.assertEqual(self.encode(terms, [1, 3]), b"\x82ab\x80\x82bc")

    def test_ids_out_of_byte_order_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "not after the previous term"):
            self.encode([b"a", b"b"], [1, 0])


if __name__ == "__main__":
    unittest.main()
