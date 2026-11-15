#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""A writable rdflib store over any number of read-only HDT stores."""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

from rdflib import Graph
from rdflib.store import Store
from rdflib.term import URIRef

from rdflib_hdt_ng.hdt_store import HdtStore

if TYPE_CHECKING:
    from rdflib.graph import _ContextType, _TriplePatternType, _TripleType

__all__ = ["HdtUnionStore"]


class HdtUnionStore(Store):
    """The union of a mutable graph and read-only HDT stores, as one writable store.

    Additions go to the mutable graph unless an HDT already holds the triple. Removing a triple
    an HDT holds records it as removed (it stays in the HDT but is no longer seen); adding it
    again, or loading another HDT that holds it, makes it seen again. The mutable graph never
    holds a triple an HDT also holds, so a scan needs no duplicate check against it; duplicates
    between HDTs are skipped. Namespace bindings are the mutable graph's.
    """

    def __init__(self, mutable: Graph | None = None) -> None:
        super().__init__()
        self._mutable = Graph() if mutable is None else mutable
        self._hdts: list[HdtStore] = []
        self._removed: set[_TripleType] = set()

    def add_hdt(self, hdt: HdtStore) -> None:
        """Add an HDT's triples to the union."""
        for triple in [t for t in self._mutable if _holds(hdt, t)]:
            self._mutable.remove(triple)
        self._removed = {t for t in self._removed if not _holds(hdt, t)}
        self._hdts.append(hdt)

    def add(self, triple: _TripleType, context: _ContextType, quoted: bool = False) -> None:
        if triple in self._removed:
            self._removed.discard(triple)
        elif not any(_holds(hdt, triple) for hdt in self._hdts):
            self._mutable.add(triple)

    def remove(self, triple: _TriplePatternType, context: _ContextType | None = None) -> None:
        self._mutable.remove(triple)
        for hdt in self._hdts:
            for held, _ in hdt.triples(triple):
                self._removed.add(held)

    def triples(
        self, triple_pattern: _TriplePatternType, context: _ContextType | None = None
    ) -> Iterator[tuple[_TripleType, Iterator[_ContextType | None]]]:
        for triple in self._mutable.triples(triple_pattern):
            yield triple, iter(())
        for k, hdt in enumerate(self._hdts):
            earlier = self._hdts[:k]
            for triple, contexts in hdt.triples(triple_pattern):
                if triple in self._removed or any(_holds(e, triple) for e in earlier):
                    continue
                yield triple, contexts

    def __len__(self, context: _ContextType | None = None) -> int:
        return sum(1 for _ in self.triples((None, None, None)))

    def bind(self, prefix: str, namespace: URIRef, override: bool = True) -> None:
        self._mutable.store.bind(prefix, namespace, override=override)

    def namespace(self, prefix: str) -> URIRef | None:
        return self._mutable.store.namespace(prefix)

    def prefix(self, namespace: URIRef) -> str | None:
        return self._mutable.store.prefix(namespace)

    def namespaces(self) -> Iterator[tuple[str, URIRef]]:
        yield from self._mutable.store.namespaces()


def _holds(hdt: HdtStore, triple: _TripleType) -> bool:
    return next(iter(hdt.triples(triple)), None) is not None
