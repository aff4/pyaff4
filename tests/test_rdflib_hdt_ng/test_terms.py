#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""HDT term strings -> rdflib terms. Literal text is stored raw: nothing is un-escaped."""

from __future__ import annotations

import re
import unittest

from rdflib.term import BNode, Literal, URIRef

from pyhdt2_cython import PyHdt
from rdflib_hdt_ng import terms
from tests import HDT_GRAPHS

XSD = "http://www.w3.org/2001/XMLSchema#"
DT = "http://ex.org/dt"

# Stored literal string -> (lexical form, language, datatype).
LITERALS = {
    '"plain"': ("plain", None, None),
    '""': ("", None, None),
    '""@en': ("", "en", None),
    '"hello"@en': ("hello", "en", None),
    '"hello"@EN-gb': ("hello", "EN-gb", None),
    f'"42"^^<{XSD}integer>': ("42", None, f"{XSD}integer"),
    f'"x"^^<{XSD}string>': ("x", None, f"{XSD}string"),
    f'"2020-01-01T00:00:00Z"^^<{XSD}dateTime>': ("2020-01-01T00:00:00Z", None, f"{XSD}dateTime"),
    # Backslashes are text, so what looks like an escape is kept as written.
    '"C:\\new"': ("C:\\new", None, None),
    '"a \\ b"': ("a \\ b", None, None),
    '"\\u00e9\\U0001F600"': ("\\u00e9\\U0001F600", None, None),
    '"trailing backslash \\"': ("trailing backslash \\", None, None),
    # Quotes are text: the lexical form ends at the last quote.
    '"""': ('"', None, None),
    '"say "hi""@en': ('say "hi"', "en", None),
    '"he said "hi"@en"': ('he said "hi"@en', None, None),
    '"ends like a datatype^^<http://ex.org/x>"': (
        "ends like a datatype^^<http://ex.org/x>",
        None,
        None,
    ),
    f'"a"^^<x>"^^<{DT}>': ('a"^^<x>', None, DT),
    # Control characters, NUL and non-ASCII are stored as themselves.
    '"two\nlines\ttab\rcr"': ("two\nlines\ttab\rcr", None, None),
    '"nul\x00inside"': ("nul\x00inside", None, None),
    '"\ufffd \U0001f600 naïve"@fr': ("\ufffd \U0001f600 naïve", "fr", None),
}


def shape(node) -> tuple:
    """Everything that distinguishes two rdflib terms."""
    if isinstance(node, Literal):
        return (Literal, str(node), node.language, node.datatype)
    return (type(node), str(node))


class LiteralTests(unittest.TestCase):
    def test_raw_literal_forms(self) -> None:
        for term, (lexical, lang, datatype) in LITERALS.items():
            with self.subTest(term=term):
                expected = Literal(lexical, lang=lang, datatype=datatype and URIRef(datatype))
                self.assertEqual(shape(terms.node_or_literal(term)), shape(expected))

    def test_every_term_in_the_fixture_files_converts(self) -> None:
        checked = 0
        for path in HDT_GRAPHS:
            for t in PyHdt(path.read_bytes()).triples():
                with self.subTest(file=path.name, term=t.object):
                    terms.node_or_literal(t.object)
                    terms.resource(t.subject)
                checked += 1
        self.assertGreater(checked, 100)

    def test_blank_nodes_and_iris(self) -> None:
        self.assertIs(type(terms.resource("_:b0")), BNode)
        self.assertIs(type(terms.node_or_literal("_:b0")), BNode)
        self.assertEqual(terms.resource("http://ex.org/s"), URIRef("http://ex.org/s"))
        self.assertIs(type(terms.node_or_literal("http://ex.org/o")), URIRef)


class MalformedLiteralTests(unittest.TestCase):
    def test_errors_name_the_problem(self) -> None:
        cases = {
            '"': "unterminated",
            # hdt-cpp stores "a\u0000b" cut off at the NUL, as "a.
            '"a': "unterminated",
            '"x"^^http://no-angle-brackets': "unrecognised suffix",
            '"x"en': "unrecognised suffix",
        }
        for term, message in cases.items():
            with self.subTest(term=term), self.assertRaisesRegex(ValueError, message):
                terms.literal(term)
            with self.subTest(term=term), self.assertRaisesRegex(ValueError, re.escape(repr(term))):
                terms.literal(term)


class CacheTests(unittest.TestCase):
    def test_repeated_strings_share_one_term(self) -> None:
        term = f'"7"^^<{XSD}integer>'
        self.assertIs(terms.node_or_literal(term), terms.node_or_literal(term))
        self.assertIs(terms.predicate("http://ex.org/p"), terms.predicate("http://ex.org/p"))


if __name__ == "__main__":
    unittest.main()
