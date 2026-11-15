#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""(S, ?P, ?O) patterns against a brute-force filter of the full scan on real HDT files."""

from __future__ import annotations

import unittest

from pyhdt2_cython import PyHdt, PyStringTriple
from pyhdt2_cython.build import from_triples
from tests import HDT_GRAPHS


def as_tuples(triples) -> list[tuple[str, str, str]]:
    return [(t.subject, t.predicate, t.object) for t in triples]


class SubjectPatternTests(unittest.TestCase):
    def assert_subject_queries_match_scan(self, hdt: PyHdt) -> None:
        scan = as_tuples(hdt.triples())
        subjects = list(dict.fromkeys(s for s, _, _ in scan))
        for s in subjects:
            got = list(hdt.triples_with_pattern(s, None, None))
            self.assertTrue(all(type(t) is PyStringTriple for t in got))
            self.assertEqual(as_tuples(got), [t for t in scan if t[0] == s], s)
        objects_only = {o for _, _, o in scan} - set(subjects)
        for term in sorted(objects_only)[:50] + ["http://absent/s", "_:absent"]:
            self.assertEqual(list(hdt.triples_with_pattern(term, None, None)), [], term)

    def test_fixture_files(self) -> None:
        for path in HDT_GRAPHS:
            with self.subTest(file=path.name):
                self.assert_subject_queries_match_scan(PyHdt(path.read_bytes()))

    def test_generated_graph_with_shared_terms_and_typed_literals(self) -> None:
        xsd = "http://www.w3.org/2001/XMLSchema#"
        triples = [
            ("http://ex.org/a", "http://ex.org/p", "http://ex.org/b"),
            ("http://ex.org/b", "http://ex.org/p", "http://ex.org/a"),
            ("http://ex.org/a", "http://ex.org/q", f'"1"^^<{xsd}integer>'),
            ("http://ex.org/a", "http://ex.org/q", '"x"@en'),
            ("_:b0", "http://ex.org/q", f'"1"^^<{xsd}long>'),
        ]
        self.assert_subject_queries_match_scan(PyHdt(from_triples(triples)))

    def test_empty_graph(self) -> None:
        hdt = PyHdt(from_triples([]))
        self.assertEqual(list(hdt.triples_with_pattern("http://s", None, None)), [])

    def test_results_are_lazy(self) -> None:
        triples = [
            ("http://ex.org/s", "http://ex.org/p", f"http://ex.org/o{i}") for i in range(500)
        ]
        it = PyHdt(from_triples(triples)).triples_with_pattern("http://ex.org/s", None, None)
        self.assertEqual(next(it).subject, "http://ex.org/s")
        self.assertEqual(sum(1 for _ in it), 499)


if __name__ == "__main__":
    unittest.main()
