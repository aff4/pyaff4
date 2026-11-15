#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""HdtUnionStore: a writable graph over read-only HDT stores."""

from __future__ import annotations

import unittest

from rdflib import XSD, BNode, Graph, Literal, Namespace, URIRef

from rdflib_hdt_ng import HdtStore, graph_to_hdt_bytes
from rdflib_hdt_ng.union_store import HdtUnionStore

EX = Namespace("http://ex.org/")
A = (EX.a, EX.p, Literal("one"))
B = (EX.b, EX.p, Literal("two"))
C = (EX.c, EX.p, Literal("three"))
D = (EX.d, EX.p, EX.a)


def hdt_of(*triples) -> HdtStore:
    g = Graph()
    for t in triples:
        g.add(t)
    return HdtStore(graph_to_hdt_bytes(g))


def union(*hdts: HdtStore, mutable: Graph | None = None) -> tuple[Graph, HdtUnionStore]:
    store = HdtUnionStore(mutable)
    for hdt in hdts:
        store.add_hdt(hdt)
    return Graph(store), store


class UnionReadTests(unittest.TestCase):
    def test_sees_every_source_once(self) -> None:
        g, _ = union(hdt_of(A, B), hdt_of(B, C))
        g.add(D)
        self.assertEqual(sorted(g), sorted([A, B, C, D]))
        self.assertEqual(len(g), 4)

    def test_mutable_triples_an_hdt_brings_are_not_doubled(self) -> None:
        mutable = Graph()
        mutable.add(A)
        mutable.add(D)
        g, store = union(mutable=mutable)
        store.add_hdt(hdt_of(A, B))
        self.assertEqual(sorted(g), sorted([A, B, D]))
        self.assertEqual(sorted(mutable), [D])

    def test_patterns_reach_every_source(self) -> None:
        g, _ = union(hdt_of(A, D), hdt_of(B))
        g.add(C)
        self.assertEqual(sorted(g.subjects(EX.p, None)), [EX.a, EX.b, EX.c, EX.d])
        self.assertEqual(list(g.subjects(EX.p, EX.a)), [EX.d])
        self.assertIn(B, g)
        self.assertNotIn((EX.b, EX.p, Literal("one")), g)


class UnionWriteTests(unittest.TestCase):
    def test_adding_an_hdt_triple_changes_nothing(self) -> None:
        mutable = Graph()
        g, _ = union(hdt_of(A), mutable=mutable)
        g.add(A)
        self.assertEqual((len(g), len(mutable)), (1, 0))

    def test_removing_hides_hdt_triples_until_added_again(self) -> None:
        g, _ = union(hdt_of(A, B))
        g.remove((None, EX.p, Literal("one")))
        self.assertEqual(list(g), [B])
        g.add(A)
        self.assertEqual(sorted(g), sorted([A, B]))

    def test_set_replaces_an_hdt_value(self) -> None:
        g, _ = union(hdt_of(A))
        g.set((EX.a, EX.p, Literal("uno")))
        self.assertEqual(list(g.objects(EX.a, EX.p)), [Literal("uno")])

    def test_a_later_hdt_brings_back_a_removed_triple(self) -> None:
        g, store = union(hdt_of(A, B))
        g.remove(A)
        store.add_hdt(hdt_of(A))
        self.assertEqual(sorted(g), sorted([A, B]))

    def test_namespaces_and_turtle_round_trip(self) -> None:
        g, _ = union(hdt_of(A, B))
        g.bind("ex", EX)
        g.add(C)
        self.assertEqual(g.namespace_manager.store.namespace("ex"), URIRef(str(EX)))
        again = Graph().parse(data=g.serialize(format="turtle"), format="turtle")
        self.assertEqual(sorted(again), sorted([A, B, C]))


class HdtStoreLookupTests(unittest.TestCase):
    def test_bound_terms_match_their_stored_form(self) -> None:
        blank = (BNode("b1"), EX.p, Literal("x\ny", datatype=XSD.string))
        tagged = (EX.s, EX.p, Literal("hi", lang="EN"))
        g = Graph(hdt_of(blank, tagged))
        self.assertEqual(len(list(g.triples((BNode("b1"), None, None)))), 1)
        self.assertEqual(len(list(g.triples((None, None, Literal("x\ny"))))), 1)
        self.assertEqual(len(list(g.triples((None, None, Literal("hi", lang="EN"))))), 1)


if __name__ == "__main__":
    unittest.main()
