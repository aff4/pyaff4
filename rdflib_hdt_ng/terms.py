#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Convert HDT term strings to rdflib terms.

HDT stores IRIs bare, blank nodes as `_:id`, and literals as `"lexical"`, `"lexical"@lang` or
`"lexical"^^<datatype>`, with the lexical form stored raw, as hdt-java and hdt-cpp store it:
nothing in it is escaped, so it may contain `"`, `\`, newlines and NUL. The lexical form ends at
the last `"`, since neither a language tag nor a datatype IRI can contain one.

Results are cached per term string: rdflib terms are immutable, and predicates, types and
subjects repeat heavily within a graph.
"""

from __future__ import annotations

from functools import lru_cache

from rdflib.term import BNode, Literal, Node, URIRef

CACHE_SIZE = 1 << 16


def literal(term: str) -> Literal:
    """The rdflib Literal for an HDT literal string such as `"chat"@fr`."""
    end = term.rfind('"')
    if end <= 0:
        raise ValueError(f"unterminated HDT literal: {term!r}")
    lexical = term[1:end]
    suffix = term[end + 1 :]
    if not suffix:
        return Literal(lexical)
    if suffix[0] == "@":
        return Literal(lexical, lang=suffix[1:])
    if suffix.startswith("^^<") and suffix.endswith(">"):
        return Literal(lexical, datatype=URIRef(suffix[3:-1]))
    raise ValueError(f"unrecognised suffix {suffix!r} on HDT literal {term!r}")


@lru_cache(maxsize=CACHE_SIZE)
def resource(term: str) -> BNode | URIRef:
    """A subject: a blank node for `_:...`, otherwise an IRI."""
    return BNode(term) if term[0] == "_" else URIRef(term)


@lru_cache(maxsize=CACHE_SIZE)
def predicate(term: str) -> URIRef:
    return URIRef(term)


@lru_cache(maxsize=CACHE_SIZE)
def node_or_literal(term: str) -> Node:
    """An object: a literal for `"...`, a blank node for `_:...`, otherwise an IRI."""
    first = term[0]
    if first == '"':
        return literal(term)
    if first == "_":
        return BNode(term)
    return URIRef(term)
