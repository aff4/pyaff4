#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

from rdflib.store import Store

# URIRef / Literal are referenced at runtime (constructor calls in triples() and
# newLiteral()), so they must be imported eagerly — not only inside TYPE_CHECKING.
from rdflib.term import BNode, Identifier, Literal, URIRef

from pyhdt2_cython import PyHdt
from rdflib_hdt_ng import terms
from rdflib_hdt_ng.rdflib_bridge import _term_str

if TYPE_CHECKING:
    from rdflib.graph import (
        _ContextType,
        _TriplePatternType,
        _TripleType,
    )

__all__ = ["HdtStore"]

ANY: None = None


def _needle(term: object) -> str | None:
    """A bound pattern term as the HDT dictionary stores it, or ANY for an unbound one."""
    if term is None:
        return ANY
    if type(term) is str:
        return '"' + term + '"'
    if isinstance(term, URIRef | Literal | BNode):
        return _term_str(term)
    return str(term)


class HdtStore(Store):
    """\
    A read-only HDT store

    `opidx_bytes` is the optional `.opidx` sidecar, which saves building the object index. A
    sidecar that doesn't match the HDT is ignored.

    Authors: Brad Schatz
    """

    def __init__(
        self,
        hdt_bytes,
        configuration: str | None = None,
        identifier: Identifier | None = None,
        *,
        opidx_bytes: bytes | None = None,
    ):
        self.identifier = identifier
        self.__namespace: dict[str, URIRef] = {}
        self.__prefix: dict[URIRef, str] = {}
        self.__hdt = PyHdt(hdt_bytes, opidx_bytes)

    def add(
        self,
        triple: _TripleType,
        context: _ContextType,
        quoted: bool = False,
    ) -> None:
        raise RuntimeError("This store is immutable")

    def remove(
        self,
        triple_pattern: _TriplePatternType,
        context: _ContextType | None = None,
    ) -> None:
        raise RuntimeError("This store is immutable")

    def triples(
        self,
        triple_pattern: _TriplePatternType,
        context: _ContextType | None = None,
    ) -> Iterator[tuple[_TripleType, Iterator[_ContextType | None]]]:
        subject, predicate, object = (_needle(term) for term in triple_pattern)
        if subject == ANY and predicate == ANY and object == ANY:
            results = self.__hdt.triples()
        else:
            results = self.__hdt.triples_with_pattern(subject, predicate, object)
        resource, predicate_term, node_or_literal = (
            terms.resource,
            terms.predicate,
            terms.node_or_literal,
        )
        for t in results:
            yield (
                (resource(t.subject), predicate_term(t.predicate), node_or_literal(t.object)),
                iter(()),
            )

    def __len__(self, context: _ContextType | None = None) -> int:
        return len(self.__hdt)

    def bind(self, prefix: str, namespace: URIRef, override: bool = True) -> None:
        raise RuntimeError("This store is immutable")

    def namespace(self, prefix: str) -> URIRef | None:
        return self.__namespace.get(prefix, None)

    def prefix(self, namespace: URIRef) -> str | None:
        return self.__prefix.get(namespace, None)

    def namespaces(self) -> Iterator[tuple[str, URIRef]]:
        yield from self.__namespace.items()

    def node(self, s: str):
        return terms.resource(s)

    def nodeOrLiteral(self, s: str):
        return terms.node_or_literal(s)

    def newLiteral(self, s: str, dt: URIRef | None, lang: str | None) -> Literal:
        if dt:
            return Literal(s, datatype=dt)
        else:
            return Literal(s, lang=lang)
