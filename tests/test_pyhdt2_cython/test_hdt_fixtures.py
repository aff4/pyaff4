#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""
Three subject terms recur: the last two contain U+0000, which the
NUL-terminated HDT v1 section (type 2) cannot store and the length-prefixed sections (types 7
and 8) can.
"""

from __future__ import annotations

import unittest

from pyhdt2_cython import _kernels as K
from pyhdt2_cython.hdt import Hdt
from tests import HDT_FIXTURES

RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
NUL_TERMS = [
    "http://example.org#ࠀbc",
    "http://example.org#ࠁ\x00d",
    "http://example.org#ࠁ\x00ghi",
]


def load(name: str) -> Hdt:
    return Hdt((HDT_FIXTURES / name).read_bytes())


class JavaHdtV1Tests(unittest.TestCase):
    """java-hdtv1.hdt, written by hdt-java."""

    def setUp(self) -> None:
        self.hdt = load("java-hdtv1.hdt")

    def test_dictionary(self) -> None:
        hdt = self.hdt
        self.assertTrue(hdt.objects.suffix_coded, "dictionaryFourPsfc")
        sections = (hdt.shared, hdt.subjects, hdt.predicates, hdt.objects)
        self.assertEqual([s.num_strings for s in sections], [0, 1, 2, 2])
        self.assertEqual(hdt.subjects.locate("http://example.org/id0"), 1)
        self.assertEqual(hdt.subjects.extract(1), "http://example.org/id0")
        self.assertEqual(hdt.objects.extract(1), '"100"^^<http://www.w3.org/2001/XMLSchema#long>')
        self.assertEqual(hdt.objects.extract(2), "http://example.org/SomeClass")

    def test_triples(self) -> None:
        self.assertEqual(
            list(self.hdt.triples()),
            [
                (
                    "http://example.org/id0",
                    "http://example.org#someproperty",
                    '"100"^^<http://www.w3.org/2001/XMLSchema#long>',
                ),
                ("http://example.org/id0", RDF_TYPE, "http://example.org/SomeClass"),
            ],
        )


class Utf8NulTermTests(unittest.TestCase):
    """Length-prefixed sections store terms containing U+0000. hdt-ng-utf8.hdt uses section type 8;
    hdt-ng-utf8-deprecated.hdt type 7 (with a trailing NUL)."""

    FILES = {
        "hdt-ng-utf8.hdt": K.ENC_LENGTH_PREFIXED,
        "hdt-ng-utf8-deprecated.hdt": K.ENC_LENGTH_PREFIXED_NUL,
    }

    def test_terms_round_trip(self) -> None:
        for name, enc in self.FILES.items():
            with self.subTest(file=name):
                hdt = load(name)
                self.assertTrue(hdt.objects.suffix_coded, "dictionaryFourPsfc")
                self.assertEqual(hdt.shared.num_strings, 0)
                self.assertEqual(hdt.subjects.num_strings, 3)
                self.assertEqual(hdt.subjects.enc, enc)
                for term in NUL_TERMS:
                    self.assertEqual(hdt.subjects.extract(hdt.subjects.locate(term)), term)

    def test_triples(self) -> None:
        expected = [(term, RDF_TYPE, "http://example.org#SomeClass") for term in NUL_TERMS]
        for name in self.FILES:
            with self.subTest(file=name):
                hdt = load(name)
                self.assertEqual(list(hdt.triples()), expected)
                self.assertEqual(list(hdt.triples_with_pattern(NUL_TERMS[2])), expected[2:])


class HdtV1NulTermTests(unittest.TestCase):
    """hdtv1-failing-utf8.hdt stores the same terms NUL-terminated (section type 2), so the second
    is cut short at its NUL and the third retains more bytes than that cut-short string has
    (test_section_read_utf8_null_failure). Where hdt-rs reports the NUL terms as absent, this
    reader rejects the malformed entry."""

    MALFORMED = "entry retains more bytes than the previous string has"

    def setUp(self) -> None:
        self.hdt = load("hdtv1-failing-utf8.hdt")
        self.subjects = self.hdt.subjects

    def test_sections(self) -> None:
        self.assertTrue(self.hdt.objects.suffix_coded, "dictionaryFourPsfc")
        shared = self.hdt.shared
        self.assertEqual((shared.num_strings, len(shared.packed), shared.block_size), (0, 0, 32))
        subjects = self.subjects
        self.assertEqual(
            (subjects.num_strings, len(subjects.packed), subjects.block_size), (3, 37, 32)
        )
        self.assertEqual(subjects.enc, K.ENC_NUL_TERMINATED)

    def test_term_before_the_nul_terms_is_found(self) -> None:
        self.assertEqual(self.subjects.locate(NUL_TERMS[0]), 1)
        self.assertEqual(self.subjects.extract(1), NUL_TERMS[0])

    def test_nul_term_is_cut_short_at_its_nul(self) -> None:
        self.assertEqual(self.subjects.extract(2), "http://example.org#ࠁ")

    def test_nul_terms_are_rejected_as_malformed(self) -> None:
        for term in NUL_TERMS[1:]:
            with self.subTest(term=term), self.assertRaisesRegex(ValueError, self.MALFORMED):
                self.subjects.locate(term)
        with self.assertRaisesRegex(ValueError, self.MALFORMED):
            self.subjects.extract(3)


if __name__ == "__main__":
    unittest.main()
