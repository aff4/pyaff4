#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Datatype suffix coding of `dictionaryFourPsfc` objects sections."""

from __future__ import annotations

import unittest

from pyhdt2_cython import _kernels as K
from pyhdt2_cython.hdt import Hdt
from tests import HDT_FIXTURES

DATATYPES = HDT_FIXTURES / "datatype-variants.hdt"
XSD_LONG = "<http://www.w3.org/2001/XMLSchema#long>"


class PsfcLiteralTests(unittest.TestCase):
    def test_typed_literal_round_trips(self) -> None:
        readable = f'"100"^^{XSD_LONG}'
        stored = f'^^{XSD_LONG}"100"'
        self.assertEqual(K.psfc_encode_if_literal(readable), stored)
        self.assertEqual(K.psfc_decode_if_literal(stored), readable)

    def test_other_terms_are_unchanged(self) -> None:
        for term in ('"plain"', '"hallo"@nl', "http://ex.org/a", "_:b0", ""):
            with self.subTest(term=term):
                self.assertEqual(K.psfc_encode_if_literal(term), term)
                self.assertEqual(K.psfc_decode_if_literal(term), term)

    def test_value_containing_the_separator_splits_at_the_last_one(self) -> None:
        readable = f'"a"^^b"^^{XSD_LONG}'
        stored = K.psfc_encode_if_literal(readable)
        self.assertEqual(stored, f'^^{XSD_LONG}"a"^^b"')
        self.assertEqual(K.psfc_decode_if_literal(stored), readable)

    def test_untyped_literals_containing_the_separator_are_unchanged(self) -> None:
        # Their text contains "^^ but they do not end in >: splitting them would store a string
        # that decodes to a different term.
        for term in ('"a"^^b"', '"a"^^b"@en', '"x"^^<http://ex.org/d>" tail"'):
            with self.subTest(term=term):
                self.assertEqual(K.psfc_encode_if_literal(term), term)
                self.assertEqual(K.psfc_decode_if_literal(term), term)


class PsfcSectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.hdt = Hdt(DATATYPES.read_bytes())

    def test_objects_section_is_suffix_coded(self) -> None:
        self.assertTrue(self.hdt.objects.suffix_coded)

    def test_objects_come_back_readable_and_locate_by_their_readable_form(self) -> None:
        objects = self.hdt.objects
        for local_id in range(1, objects.num_strings + 1):
            readable = objects.extract(local_id)
            with self.subTest(readable=readable):
                self.assertFalse(readable.startswith("^^"))
                self.assertEqual(objects.locate(readable), local_id)

    def test_object_queries_use_the_readable_form(self) -> None:
        literal = f'"100"^^{XSD_LONG}'
        found = list(self.hdt.triples_with_pattern(None, None, literal))
        self.assertTrue(found)
        for triple in found:
            self.assertEqual(triple[2], literal)
            self.assertTrue(self.hdt.has_triple(*triple))


if __name__ == "__main__":
    unittest.main()
