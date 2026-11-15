#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Tests for the in-memory HDT construction APIs (read_nt_slice, from_triples)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pyhdt2_cython import PyHdt


class FromTriplesTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_from_triples_round_trips_a_simple_graph(self) -> None:
        triples = [
            ("http://example.org/s1", "http://example.org/p", "http://example.org/o1"),
            ("http://example.org/s2", "http://example.org/p", '"hello"@en'),
        ]
        hdt = PyHdt.from_triples(triples)
        out = self.tmp_path / "round.hdt"
        hdt.write(str(out))

        reloaded = PyHdt(out.read_bytes())
        got = sorted((t.subject, t.predicate, t.object) for t in reloaded.triples())
        self.assertEqual(len(got), 2)
        self.assertTrue(any("hello" in o for _, _, o in got))

    def test_from_triples_tolerates_angle_bracketed_iris(self) -> None:
        triples = [("<http://a/s>", "<http://a/p>", "<http://a/o>")]
        hdt = PyHdt.from_triples(triples)
        out = self.tmp_path / "brackets.hdt"
        hdt.write(str(out))
        reloaded = PyHdt(out.read_bytes())
        s, p, o = next(iter([(t.subject, t.predicate, t.object) for t in reloaded.triples()]))
        self.assertEqual((s, p, o), ("http://a/s", "http://a/p", "http://a/o"))

    def test_from_triples_empty_input(self) -> None:
        hdt = PyHdt.from_triples([])
        out = self.tmp_path / "empty.hdt"
        hdt.write(str(out))
        reloaded = PyHdt(out.read_bytes())
        self.assertEqual(sum(1 for _ in reloaded.triples()), 0)

    def test_from_triples_accepts_explicit_base_iri(self) -> None:
        triples = [("http://a/s", "http://a/p", "http://a/o")]
        hdt = PyHdt.from_triples(triples, base_iri="aff4://my-dataset")
        out = self.tmp_path / "custom-base.hdt"
        hdt.write(str(out))
        reloaded = PyHdt(out.read_bytes())
        self.assertEqual(sum(1 for _ in reloaded.triples()), 1)

    def test_terms_containing_nul_round_trip_and_are_found(self) -> None:
        shared = "http://example.org/a\x00b"
        triples = [
            (shared, "http://example.org/p\x00", "http://example.org/o\x00"),
            ("http://example.org/s", "http://example.org/p", shared),
            ("_:blank\x00node", "http://example.org/p", '"lit\x00eral"'),
            ("http://example.org/s", "http://example.org/p", '"x\x00"@en'),
            ("http://example.org/s", "http://example.org/p", '"\x00"^^<http://example.org/dt>'),
        ]
        hdt = PyHdt.from_triples(triples)
        got = sorted((t.subject, t.predicate, t.object) for t in hdt.triples())
        self.assertEqual(got, sorted(triples))
        for s, p, o in triples:
            with self.subTest(triple=(s, p, o)):
                self.assertEqual(len(list(hdt.triples_with_pattern(s, p, o))), 1)
                self.assertIn(
                    (s, p, o),
                    {
                        (t.subject, t.predicate, t.object)
                        for t in hdt.triples_with_pattern(None, None, o)
                    },
                )


if __name__ == "__main__":
    unittest.main()
