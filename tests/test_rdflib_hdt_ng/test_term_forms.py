#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""rdflib terms as graph_to_hdt_bytes stores them: literal text raw, as hdt-java and hdt-cpp do."""

from __future__ import annotations

import unittest

from rdflib import XSD, BNode, Graph, Literal, URIRef
from rdflib.term import Variable

from pyhdt2_cython import PyHdt
from rdflib_hdt_ng import graph_to_hdt_bytes
from rdflib_hdt_ng.terms import node_or_literal

S = URIRef("http://ex.org/s")
P = URIRef("http://ex.org/p")
DT = "http://ex.org/dt"


def stored(obj) -> str:
    """The stored object for one rdflib object term, read back through PyHdt."""
    g = Graph()
    g.add((S, P, obj))
    (triple,) = list(PyHdt(graph_to_hdt_bytes(g)).triples())
    return triple.object


class LiteralFormTests(unittest.TestCase):
    def test_string_literal_is_stored_raw(self) -> None:
        value = 'a\\b "q" \n \t \r \f \ufffd \b \x01 \x00 C:\\new \\u0041'
        self.assertEqual(stored(Literal(value)), f'"{value}"')

    def test_xsd_string_is_implied(self) -> None:
        self.assertEqual(stored(Literal("x\ty", datatype=XSD.string)), '"x\ty"')

    def test_language_tag_is_lowercased_and_value_raw(self) -> None:
        self.assertEqual(stored(Literal('x"y\\', lang="EN-GB")), '"x"y\\"@en-gb')

    def test_plain_and_tagged_text_that_looks_typed_is_not_suffix_coded(self) -> None:
        for literal in (Literal('a"^^<http://ex.org/x>'), Literal('a"^^<x>', lang="en")):
            with self.subTest(literal=literal):
                self.assertEqual(node_or_literal(stored(literal)), literal)

    def test_typed_literal_is_stored_raw_and_found(self) -> None:
        value = 'a"b\\c\nd\t\r\f\ufffd\x00 x"^^<http://ex.org/other>'
        g = Graph()
        g.add((S, P, Literal(value, datatype=URIRef(DT))))
        hdt = PyHdt(graph_to_hdt_bytes(g))
        (triple,) = list(hdt.triples())
        self.assertEqual(triple.object, f'"{value}"^^<{DT}>')
        self.assertEqual(len(list(hdt.triples_with_pattern(None, None, triple.object))), 1)

    def test_typed_literal_reads_back_through_rdflib(self) -> None:
        literal = Literal('a"b\\c\nd', datatype=URIRef(DT))
        self.assertEqual(node_or_literal(stored(literal)), literal)


class NodeFormTests(unittest.TestCase):
    def test_iris_are_bare_and_blank_labels_kept(self) -> None:
        g = Graph()
        g.add((BNode("node1"), P, URIRef("http://ex.org/ü")))
        (triple,) = list(PyHdt(graph_to_hdt_bytes(g)).triples())
        self.assertEqual((triple.subject, triple.object), ("_:node1", "http://ex.org/ü"))

    def test_other_terms_are_rejected(self) -> None:
        g = Graph()
        g.add((S, P, Variable("v")))
        with self.assertRaisesRegex(TypeError, "cannot store Variable"):
            graph_to_hdt_bytes(g)


if __name__ == "__main__":
    unittest.main()
