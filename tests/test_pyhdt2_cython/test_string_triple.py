#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""PyStringTriple, the result object yielded by PyHdt.triples and triples_with_pattern."""

from __future__ import annotations

import unittest

from pyhdt2_cython import PyHdt, PyStringTriple

TRIPLES = [
    ("http://a/s1", "http://a/p1", "http://a/o1"),
    ("http://a/s1", "http://a/p2", '"hello"@en'),
    ("_:b0", "http://a/p1", '"naïve"'),
]


class PyStringTripleTests(unittest.TestCase):
    def test_query_results_are_string_triples_with_the_stored_terms(self) -> None:
        hdt = PyHdt.from_triples(TRIPLES)
        got = list(hdt.triples())
        self.assertTrue(all(type(t) is PyStringTriple for t in got))
        self.assertEqual(sorted((t.subject, t.predicate, t.object) for t in got), sorted(TRIPLES))
        by_s = list(hdt.triples_with_pattern("http://a/s1", None, None))
        self.assertTrue(all(type(t) is PyStringTriple for t in by_s))
        self.assertEqual({t.subject for t in by_s}, {"http://a/s1"})

    def test_attributes_are_read_only(self) -> None:
        t = PyStringTriple("s", "p", "o")
        for name in ("subject", "predicate", "object"):
            with self.subTest(name=name), self.assertRaises(AttributeError):
                setattr(t, name, "x")
        self.assertEqual((t.subject, t.predicate, t.object), ("s", "p", "o"))

    def test_repr_shows_all_three_terms(self) -> None:
        self.assertEqual(repr(PyStringTriple("s", "p", '"o"')), "PyStringTriple('s', 'p', '\"o\"')")

    def test_iterating_pyhdt_yields_string_triples(self) -> None:
        got = list(PyHdt.from_triples(TRIPLES))
        self.assertEqual(len(got), len(TRIPLES))
        self.assertTrue(all(type(t) is PyStringTriple for t in got))


if __name__ == "__main__":
    unittest.main()
