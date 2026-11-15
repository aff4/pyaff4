#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Smoke tests for the PyHdt query APIs (triples, len, triples_with_pattern, subjects_with_po)."""

from __future__ import annotations

import unittest

from pyhdt2_cython import PyHdt
from tests import HDT_GRAPHS


class PyHdtQueryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.triples = [
            ("http://a/s1", "http://a/p1", "http://a/o1"),
            ("http://a/s1", "http://a/p2", '"hello"@en'),
            ("http://a/s2", "http://a/p1", "http://a/o1"),
            ("http://a/s2", "http://a/p2", '"world"@en'),
        ]
        self.hdt = PyHdt.from_triples(self.triples)

    def test_triples_iterates_all_triples(self) -> None:
        got = sorted((t.subject, t.predicate, t.object) for t in self.hdt.triples())
        self.assertEqual(len(got), 4)

    def test_triples_with_pattern_filters_by_subject(self) -> None:
        got = [
            (t.subject, t.predicate, t.object)
            for t in self.hdt.triples_with_pattern("http://a/s1", None, None)
        ]
        self.assertEqual(len(got), 2)
        self.assertTrue(all(s == "http://a/s1" for s, _, _ in got))

    def test_subjects_with_po_returns_matching_subjects(self) -> None:
        got = sorted(self.hdt.subjects_with_po("http://a/p1", "http://a/o1"))
        self.assertEqual(got, ["http://a/s1", "http://a/s2"])

    def test_len_is_the_triple_count(self) -> None:
        self.assertEqual(len(self.hdt), 4)

    def test_len_matches_a_full_scan_of_each_fixture(self) -> None:
        for p in HDT_GRAPHS:
            with self.subTest(file=p.name):
                hdt = PyHdt(p.read_bytes())
                self.assertEqual(len(hdt), sum(1 for _ in hdt.triples()))

    def test_len_of_an_empty_graph(self) -> None:
        self.assertEqual(len(PyHdt.from_triples([])), 0)


if __name__ == "__main__":
    unittest.main()
