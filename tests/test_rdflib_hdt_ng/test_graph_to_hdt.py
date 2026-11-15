#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Tests for the rdflib Graph -> HDT bridge (graph_to_hdt)."""

from __future__ import annotations

import random
import tempfile
import unittest
from pathlib import Path

from rdflib import BNode, Graph, Literal, URIRef
from rdflib.compare import isomorphic
from rdflib.namespace import RDF, XSD

from pyhdt2_cython import PyHdt
from rdflib_hdt_ng import HdtStore, graph_to_hdt, graph_to_hdt_bytes


class GraphToHdtTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_graph_to_hdt_round_trips_an_rdflib_graph(self) -> None:
        g = Graph()
        s = URIRef("http://example.org/s")
        p = URIRef("http://example.org/p")
        g.add((s, p, Literal("plain")))
        g.add((s, p, Literal("typed", datatype=XSD.string)))
        g.add((s, p, Literal("tagged", lang="en")))
        g.add((s, RDF.type, URIRef("http://example.org/Thing")))
        g.add((s, p, BNode("b1")))

        out = self.tmp_path / "graph.hdt"
        graph_to_hdt(g, str(out))

        reloaded = PyHdt(out.read_bytes())
        triples = list(reloaded.triples())
        self.assertEqual(len(triples), len(g))
        objects = {t.object for t in triples}
        self.assertTrue(any('"plain"' in o for o in objects))
        self.assertTrue(any("@en" in o for o in objects))
        self.assertTrue(any(o.startswith("_:") for o in objects))

    def small_graph(self) -> Graph:
        g = Graph()
        s = URIRef("http://example.org/s")
        g.add((s, URIRef("http://example.org/p"), Literal(42)))
        g.add((URIRef("http://example.org/t"), URIRef("http://example.org/p"), Literal("x")))
        return g

    def test_options_reach_the_engine(self) -> None:
        out = self.tmp_path / "graph.hdt"
        graph_to_hdt(self.small_graph(), str(out), original_size=123, psfc=False)
        data = out.read_bytes()
        self.assertIn(b'<http://purl.org/HDT/hdt#originalSize> "123" .', data)
        self.assertIn(b"$HDT\x03<http://purl.org/HDT/hdt#dictionaryFour>\x00", data)
        graph_to_hdt(self.small_graph(), str(out))
        self.assertIn(b"$HDT\x03<http://purl.org/HDT/hdt#dictionaryFourPsfc>\x00", out.read_bytes())
        typed = '"42"^^<http://www.w3.org/2001/XMLSchema#integer>'
        self.assertIn(typed, {t.object for t in PyHdt(out.read_bytes()).triples()})


EX = "http://example.org/"
P = URIRef(EX + "p")
DT = URIRef(EX + "dt")
# Text that is special to literal syntax, to front coding or to UTF-8 ordering.
EDGE_TEXT = [
    "a",
    "b",
    "\\",
    '"',
    "\n",
    "\t",
    "\r",
    "\f",
    "\x00",
    "\x01",
    "@",
    "^",
    "<",
    ">",
    " ",
    '"^^<',
    '"@en',
    "\\n",
    "\\u0041",
    "é",
    "e\u0301",
    "\ufffd",
    "\uff21",
    "\U0001f600",
]
# rdflib warns about IRIs containing <>" {}|\^`, so IRIs draw from a narrower set.
EDGE_IRI = ["a", "b", "/", "#", "%20", "?", "=", "\x00", "é", "\uff21", "\U0001f600"]


def reread(g: Graph) -> Graph:
    """`g` written by graph_to_hdt_bytes and read back through HdtStore, copied into memory."""
    out = Graph()
    for triple in Graph(HdtStore(graph_to_hdt_bytes(g))):
        out.add(triple)
    return out


def random_graph(seed: int) -> Graph:
    rng = random.Random(seed)

    def text(alphabet: list[str], longest: int) -> str:
        return "".join(rng.choices(alphabet, k=rng.randrange(longest)))

    iris = [URIRef(EX + text(EDGE_IRI, 6) + str(i)) for i in range(40)]
    blanks = [BNode(f"b{i}") for i in range(5)]
    g = Graph()
    for _ in range(300):
        subject = rng.choice(iris + blanks)
        kind = rng.randrange(5)
        if kind == 0:
            obj = rng.choice(iris + blanks)
        elif kind == 1:
            obj = Literal(text(EDGE_TEXT, 8), lang=rng.choice(["en", "de-at", "zh-hant-tw"]))
        elif kind == 2:
            obj = Literal(text(EDGE_TEXT, 8), datatype=DT)
        else:
            obj = Literal(text(EDGE_TEXT, 8))
        g.add((subject, rng.choice([P, RDF.type, URIRef(EX + text(EDGE_IRI, 3))]), obj))
    return g


class RawLiteralRoundTripTests(unittest.TestCase):
    """Literals are stored raw, so whatever text a literal holds comes back unchanged."""

    def test_special_literals_round_trip_and_are_found(self) -> None:
        values = [
            "C:\\Users\\new\\file.txt",
            'say "hi"',
            'he said "hi"@en',
            'x"^^<' + EX + "o>",
            "one\ntwo",
            "nul\x00",
            "\\u00e9",
            "",
            '"',
            "\\",
            "\ufffd",
        ]
        g = Graph()
        s = URIRef(EX + "s")
        for v in values:
            g.add((s, P, Literal(v)))
            g.add((s, P, Literal(v, lang="en")))
            g.add((s, P, Literal(v, datatype=DT)))
        back = reread(g)
        self.assertTrue(isomorphic(back, g))
        store = Graph(HdtStore(graph_to_hdt_bytes(g)))
        for o in g.objects():
            with self.subTest(literal=o):
                self.assertEqual(list(store.triples((None, P, o))), [(s, P, o)])

    def test_seeded_random_graphs_round_trip_and_are_found(self) -> None:
        for seed in range(8):
            g = random_graph(seed)
            store = Graph(HdtStore(graph_to_hdt_bytes(g)))
            with self.subTest(seed=seed):
                back = Graph()
                for triple in store:
                    back.add(triple)
                self.assertTrue(isomorphic(back, g))
            for s, p, o in g:
                if isinstance(s, BNode) or isinstance(o, BNode):
                    continue  # Blank labels change on the way through HDT; isomorphism covers them.
                with self.subTest(seed=seed, triple=(s, p, o)):
                    self.assertEqual(list(store.triples((s, p, o))), [(s, p, o)])
                    self.assertIn((s, p, o), set(store.triples((None, None, o))))


if __name__ == "__main__":
    unittest.main()
