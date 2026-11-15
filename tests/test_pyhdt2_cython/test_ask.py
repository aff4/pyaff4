#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""ASK (fully bound triple patterns) against brute-force membership on real HDT files."""

from __future__ import annotations

import random
import unittest

from pyhdt2_cython import PyHdt, PyStringTriple
from pyhdt2_cython.build import from_triples
from tests import HDT_GRAPHS


def as_tuples(hdt: PyHdt) -> list[tuple[str, str, str]]:
    return [(t.subject, t.predicate, t.object) for t in hdt.triples()]


class AskTests(unittest.TestCase):
    def assert_ask_matches_membership(self, hdt: PyHdt, triples: list[tuple[str, str, str]]):
        present = set(triples)
        subjects = sorted({s for s, _, _ in triples})
        predicates = sorted({p for _, p, _ in triples})
        objects = sorted({o for _, _, o in triples})
        rng = random.Random(3)
        candidates = list(triples)
        for _ in range(2000):
            candidates.append((rng.choice(subjects), rng.choice(predicates), rng.choice(objects)))
        # Strings absent from each position, including terms that exist in another position.
        candidates += [
            ("http://absent/s", predicates[0], objects[0]),
            (subjects[0], "http://absent/p", objects[0]),
            (subjects[0], predicates[0], "http://absent/o"),
            (subjects[0], predicates[0], '"absent literal"'),
            (predicates[0], predicates[0], objects[0]),
            (subjects[0], subjects[0], objects[0]),
        ]
        for s, p, o in candidates:
            got = list(hdt.triples_with_pattern(s, p, o))
            want = (s, p, o) in present
            self.assertEqual(len(got), int(want), (s, p, o))
            if want:
                self.assertIs(type(got[0]), PyStringTriple)
                self.assertEqual((got[0].subject, got[0].predicate, got[0].object), (s, p, o))

    def test_fixture_files(self) -> None:
        for path in HDT_GRAPHS:
            with self.subTest(file=path.name):
                hdt = PyHdt(path.read_bytes())
                self.assert_ask_matches_membership(hdt, as_tuples(hdt))

    def test_generated_graph_with_shared_terms_and_typed_literals(self) -> None:
        xsd = "http://www.w3.org/2001/XMLSchema#"
        triples = [
            ("http://ex.org/a", "http://ex.org/p", "http://ex.org/b"),
            ("http://ex.org/b", "http://ex.org/p", "http://ex.org/a"),
            ("http://ex.org/a", "http://ex.org/q", f'"1"^^<{xsd}integer>'),
            ("http://ex.org/b", "http://ex.org/q", f'"1"^^<{xsd}long>'),
            ("_:b0", "http://ex.org/q", '"x"@en'),
        ]
        hdt = PyHdt(from_triples(triples))
        self.assert_ask_matches_membership(hdt, as_tuples(hdt))

    def test_empty_graph_answers_false(self) -> None:
        hdt = PyHdt(from_triples([]))
        self.assertEqual(list(hdt.triples_with_pattern("http://s", "http://p", "http://o")), [])


if __name__ == "__main__":
    unittest.main()
