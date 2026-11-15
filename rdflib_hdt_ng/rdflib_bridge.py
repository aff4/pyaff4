#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Convert rdflib graphs to HDT in-process via the pyhdt2_cython builder."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from rdflib import BNode, Literal, URIRef

from pyhdt2_cython import build

if TYPE_CHECKING:
    from rdflib import Graph

XSD_STRING = "http://www.w3.org/2001/XMLSchema#string"


def _literal(value: str, datatype: str | None, lang: str | None) -> str:
    """A literal's dictionary string: `"value"`, `"value"@lang` or `"value"^^<datatype>`.

    The lexical form is stored raw, as hdt-java and hdt-cpp store it: no character is escaped,
    since a reader finds the end of the lexical form at the last `"`. Language tags are lowercased
    and xsd:string is implied.
    """
    if lang is not None:
        return f'"{value}"@{lang.lower()}'
    if datatype is None or datatype == XSD_STRING:
        return f'"{value}"'
    return f'"{value}"^^<{datatype}>'


def _term_str(t: object) -> str:
    """An rdflib term in the form the HDT four-section dictionary stores, as the Java HDT writer
    stores it: an IRI bare (no <>), a blank node as `_:label`, a literal as `_literal` writes it.
    """
    if isinstance(t, URIRef):
        return str(t)
    if isinstance(t, Literal):
        datatype = None if t.datatype is None else str(t.datatype)
        return _literal(str(t), datatype, t.language)
    if isinstance(t, BNode):
        return f"_:{t}"
    raise TypeError(f"cannot store {type(t).__name__} {t!r} in HDT: not an IRI, blank or literal")


def graph_to_hdt_bytes(
    graph: Graph,
    *,
    base_iri: str = "urn:hdt:in-memory",
    original_size: int | None = None,
    psfc: bool = True,
) -> bytes:
    """An rdflib Graph as HDT file bytes.

    `original_size` (the source's size in bytes, e.g. of a parsed Turtle file) is written as
    hdt:originalSize; `psfc` chooses a dictionaryFourPsfc (default) or plain dictionaryFour
    dictionary.
    """
    triples = ((_term_str(s), _term_str(p), _term_str(o)) for s, p, o in graph)
    return build.from_triples(triples, base_iri, original_size=original_size, psfc=psfc)


def graph_to_hdt(
    graph: Graph,
    dest: str,
    *,
    base_iri: str = "urn:hdt:in-memory",
    original_size: int | None = None,
    psfc: bool = True,
) -> None:
    """Serialize an rdflib Graph to an HDT file at `dest`; options as for graph_to_hdt_bytes."""
    data = graph_to_hdt_bytes(graph, base_iri=base_iri, original_size=original_size, psfc=psfc)
    try:
        Path(dest).write_bytes(data)
    except OSError as e:
        raise ValueError(f"write {dest}: {e}") from e
