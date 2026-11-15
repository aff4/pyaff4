#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

import base64
import unittest
from datetime import datetime
from os import path
from unittest import mock

import rdflib
from rdflib import XSD, BNode, Literal, URIRef
from rdflib.compare import isomorphic

from pyhdt2_cython.build import write_opidx_sidecar
from pyhdt2_cython.hdt import Hdt
from rdflib_hdt_ng import hdt_store
from rdflib_hdt_ng.hdt_store import HdtStore
from tests import HDT_FIXTURES

VOCAB = "http://example.org/vocab#"
BASE_TYPE = URIRef(VOCAB + "BaseType")
BROADER = URIRef(VOCAB + "broader")
LABEL = URIRef(VOCAB + "label")
VALUE = URIRef(VOCAB + "value")


def read(directory, name):
    with open(path.join(directory, name), "rb") as f:
        return f.read()


class HDTStoreTests(unittest.TestCase):
    def test_datatype_variants(self):
        with open(path.join(HDT_FIXTURES, "datatype-variants.hdt"), "rb") as f:
            hdt_bytes = f.read()
            store = HdtStore(hdt_bytes)
            g = rdflib.Graph(store)
            it = g.triples((None, None, None))
            (s, p, o) = next(it)
            self.assertIsInstance(s, URIRef)
            self.assertEqual("http://example.org/id0", s.toPython())
            self.assertIsInstance(p, URIRef)
            self.assertEqual("http://example.org#someproperty", p.toPython())
            self.assertIsInstance(o, Literal)
            self.assertEqual("stringliteral", o.toPython())
            (s, p, o) = next(it)
            self.assertIsInstance(o, Literal)
            self.assertEqual("d5825dc1152a42958c8219ff11ed01a3", str(o))
            self.assertEqual("http://aff4.org/Schema#MD5", o.datatype.toPython())
            (s, p, o) = next(it)
            self.assertIsInstance(o, Literal)
            self.assertEqual("fbac22cca549310bc5df03b7560afcf490995fbb", str(o))
            self.assertEqual("http://aff4.org/Schema#SHA1", o.datatype.toPython())
            (s, p, o) = next(it)
            self.assertIsInstance(o, Literal)
            self.assertEqual(
                "fa45210ef4803f071aafa192448b2acd08f54daff9abfabf36dec206841a1b1f"
                "d2148690163f247e6cb1e6aa10623c17980deb125f1782f953ef269b89b1dbca",
                str(o),
            )
            self.assertEqual("http://aff4.org/Schema#SHA512", o.datatype.toPython())
            (s, p, o) = next(it)
            self.assertIsInstance(o, Literal)
            self.assertEqual(
                "e044f2212488dc8f5b66218d815e88c3d92351f506529dc7f6abb767cf1c5f1d"
                "205deb5b24f33032bf76a49abc2832a174e1c135601f43e87a4556782878afac",
                str(o),
            )
            self.assertEqual(
                "http://aff4.org/Schema#linearBlockMapHashSHA512", o.datatype.toPython()
            )
            (s, p, o) = next(it)
            self.assertIsInstance(o, Literal)
            self.assertEqual(base64.b64decode("IkhlbGxvIEFEUyI="), o.toPython())
            self.assertEqual("http://www.w3.org/2001/XMLSchema#base64Binary", o.datatype.toPython())
            (s, p, o) = next(it)
            self.assertIsInstance(o, Literal)
            self.assertEqual(True, o.toPython())
            self.assertEqual("http://www.w3.org/2001/XMLSchema#boolean", o.datatype.toPython())
            (s, p, o) = next(it)
            self.assertIsInstance(o, Literal)
            self.assertEqual(datetime.fromisoformat("1970-01-01T00:00:00+00:00"), o.toPython())
            self.assertEqual("http://www.w3.org/2001/XMLSchema#dateTime", o.datatype.toPython())
            (s, p, o) = next(it)
            self.assertIsInstance(o, Literal)
            self.assertEqual(100, o.toPython())
            self.assertEqual("http://www.w3.org/2001/XMLSchema#long", o.datatype.toPython())
            (s, p, o) = next(it)
            self.assertIsInstance(o, Literal)
            self.assertEqual(100, o.toPython())
            self.assertEqual("http://www.w3.org/2001/XMLSchema#long", o.datatype.toPython())
            with self.assertRaises(StopIteration):
                next(it)

    def test_hdt_utf8_ng(self):
        """HDT-NG PlainFrontCodingUtf8 = 8 dictionary section reads NUL-bearing strings."""
        with open(path.join(HDT_FIXTURES, "hdt-ng-utf8.hdt"), "rb") as f:
            hdt_bytes = f.read()
            store = HdtStore(hdt_bytes)
            g = rdflib.Graph(store)
            it = g.triples((None, None, None))
            (s, _, _) = next(it)
            self.assertEqual("http://example.org#ࠀbc", s.toPython())
            (s, _, _) = next(it)
            self.assertEqual("http://example.org#ࠁ\x00d", s.toPython())
            (s, _, _) = next(it)
            self.assertEqual("http://example.org#ࠁ\x00ghi", s.toPython())
            with self.assertRaises(StopIteration):
                next(it)

    def test_hdt_utf8_ng_deprecated(self):
        """Deprecated variant of the HDT-NG UTF-8 dictionary section type."""
        with open(path.join(HDT_FIXTURES, "hdt-ng-utf8-deprecated.hdt"), "rb") as f:
            hdt_bytes = f.read()
            store = HdtStore(hdt_bytes)
            g = rdflib.Graph(store)
            it = g.triples((None, None, None))
            (s, _, _) = next(it)
            self.assertEqual("http://example.org#ࠀbc", s.toPython())
            (s, _, _) = next(it)
            self.assertEqual("http://example.org#ࠁ\x00d", s.toPython())
            (s, _, _) = next(it)
            self.assertEqual("http://example.org#ࠁ\x00ghi", s.toPython())
            with self.assertRaises(StopIteration):
                next(it)

    def test_language_literal_search(self):
        g = rdflib.Graph(HdtStore(read(HDT_FIXTURES, "synthetic.hdt")))
        found = [s for s, _, _ in g.triples((None, LABEL, Literal("ХОББИ", lang="ru")))]
        self.assertEqual(found, [URIRef("http://example.org/item/хобби")])

    def test_plain_literal_search(self):
        g = rdflib.Graph(HdtStore(read(HDT_FIXTURES, "synthetic.hdt")))
        for obj in (Literal("meta"), "meta"):
            with self.subTest(obj=obj):
                found = [s for s, _, _ in g.triples((None, VALUE, obj))]
                self.assertEqual(found, [URIRef("http://example.org/item/forms")])

    def test_len_matches_a_full_scan(self):
        for name in ("synthetic.hdt", "datatype-variants.hdt", "hdt-ng-utf8.hdt"):
            with self.subTest(file=name), open(path.join(HDT_FIXTURES, name), "rb") as f:
                g = rdflib.Graph(HdtStore(f.read()))
                self.assertGreater(len(g), 0)
                self.assertEqual(len(g), sum(1 for _ in g.triples((None, None, None))))


def as_jena_stores(g: rdflib.Graph) -> rdflib.Graph:
    """`g` as Jena (and so hdt-java) stores it: "v"^^xsd:string as "v", language tags lowercased."""
    out = rdflib.Graph()
    for s, p, o in g:
        if isinstance(o, Literal) and o.datatype == XSD.string:
            o = Literal(str(o))
        elif isinstance(o, Literal) and o.language:
            o = Literal(str(o), lang=o.language.lower())
        out.add((s, p, o))
    return out


# Lookups that miss on files from other writers (tests/hdt_fixtures/README.md): rdflib rewrites
# some typed lexical forms when it builds a Literal, and lookups lowercase language tags, which
# hdt-cpp stores as written.
NORMALISED_LEXICAL_FORMS = {
    Literal("2016-12-07T03:40:09.131Z", datatype=XSD.dateTime),
    Literal("1.0E0", datatype=XSD.double),
}
MIXED_CASE_TAGS = {
    Literal("colour", lang="en-GB"),
    Literal("color", lang="en-US"),
    Literal("顏色", lang="zh-Hant-TW"),
}


class ThirdPartyWriterTests(unittest.TestCase):
    """synthetic.ttl as hdt-cpp and hdt-java convert it. Both store literal text raw."""

    def setUp(self):
        self.turtle = rdflib.Graph().parse(path.join(HDT_FIXTURES, "synthetic.ttl"))

    def check(self, name: str, expected: rdflib.Graph, known_misses: set[Literal]) -> None:
        store = rdflib.Graph(HdtStore(read(HDT_FIXTURES, name)))
        back = rdflib.Graph()
        for triple in store:
            back.add(triple)
        self.assertTrue(isomorphic(back, expected))
        misses = set()
        for s, p, o in expected:
            if isinstance(s, BNode) or isinstance(o, BNode):
                continue  # Blank labels change on the way through HDT; isomorphism covers them.
            if isinstance(o, Literal) and o.datatype == XSD.string:
                continue  # Lookups write "v"^^xsd:string as "v".
            if list(store.triples((s, p, o))) != [(s, p, o)]:
                misses.add(o)
        self.assertEqual(misses, known_misses)

    def test_hdt_cpp_conversion_matches_the_turtle(self):
        self.check("synthetic.hdt", self.turtle, NORMALISED_LEXICAL_FORMS | MIXED_CASE_TAGS)

    def test_hdt_java_conversion_matches_the_turtle(self):
        expected = as_jena_stores(self.turtle)
        self.check("synthetic-java.hdt", expected, NORMALISED_LEXICAL_FORMS)


class HdtStoreSidecarTests(unittest.TestCase):
    def test_object_queries_match_with_a_sidecar_built_for_the_graph(self):
        hdt_bytes = read(HDT_FIXTURES, "synthetic.hdt")
        opidx = write_opidx_sidecar(*Hdt(hdt_bytes).op_index_arrays())
        self.assertEqual(Hdt(hdt_bytes, opidx).sidecar_status, {"opidx": "used"})
        plain = rdflib.Graph(HdtStore(hdt_bytes))
        with_sidecar = rdflib.Graph(HdtStore(hdt_bytes, opidx_bytes=opidx))
        for pattern in ((None, None, BASE_TYPE), (None, BROADER, BASE_TYPE)):
            with self.subTest(pattern=pattern):
                expected = sorted(plain.triples(pattern))
                self.assertGreater(len(expected), 0)
                self.assertEqual(expected, sorted(with_sidecar.triples(pattern)))

    def test_sidecar_is_passed_to_the_engine(self):
        engine = mock.Mock()
        with mock.patch.object(hdt_store, "PyHdt", engine):
            HdtStore(b"hdt", opidx_bytes=b"opidx")
        engine.assert_called_once_with(b"hdt", b"opidx")


if __name__ == "__main__":
    unittest.main()
