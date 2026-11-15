#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Prefix + suffix search over front-coded sections, checked against a brute-force scan."""

from __future__ import annotations

import unittest
from os import path

from pyhdt2_cython import PyHdt
from pyhdt2_cython.hdt import PfcSection, _Reader
from tests import HDT_FIXTURES
from tests.test_pyhdt2_cython.test_front_coding import (
    TYPE_LEN,
    TYPE_LEN_NUL,
    TYPE_NUL,
    make_section,
    sample_terms,
    section_bytes,
)

TYPES = (TYPE_NUL, TYPE_LEN_NUL, TYPE_LEN)


def scan(terms: list[bytes], prefix: bytes, suffix: bytes) -> list[tuple[int, str]]:
    if not prefix:
        return []
    return [
        (i, t.decode())
        for i, t in enumerate(terms, 1)
        if t.startswith(prefix) and t.endswith(suffix)
    ]


def prefixes_of(terms: list[bytes]) -> list[bytes]:
    """Prefixes that hit block heads, run boundaries, gaps between terms, and nothing at all."""
    out = {b"\x01", b"\xff", terms[0][:1], terms[-1] + b"z"}
    for t in terms[::5]:
        out |= {t, t[:1], t[: len(t) // 2], t[:-1], t + b"!", t[:-1] + b"\xff"}
    return sorted(p for p in out if p)


class SectionAffixTests(unittest.TestCase):
    def test_matches_a_scan_for_every_type_and_block_size(self) -> None:
        terms = sample_terms(300, seed=11)
        for stype in TYPES:
            for block in (1, 2, 3, 4, 16, 1000):
                section = make_section(stype, terms, block)
                for prefix in prefixes_of(terms):
                    for suffix in (b"", b"1", b"a1", b"zz"):
                        with self.subTest(type=stype, block=block, prefix=prefix, suffix=suffix):
                            self.assertEqual(
                                section.pfc.affix(prefix, suffix), scan(terms, prefix, suffix)
                            )

    def test_named_cases(self) -> None:
        terms = [b"aaa", b"abb", b"abc", b"abd", b"abe", b"ace", b"bbb", b"bbc", b"bbd", b"ccc"]
        section = make_section(TYPE_NUL, terms, 4)
        cases = {
            "run crossing a block boundary": ("ab", None, ["abb", "abc", "abd", "abe"]),
            "prefix equal to a block's first string": ("abe", None, ["abe"]),
            "prefix equal to the first string": ("aaa", None, ["aaa"]),
            "suffix narrowing the run": ("ab", "d", ["abd"]),
            "suffix removing every match": ("ab", "z", []),
            # "abd" stores only "d" after retaining "ab": these suffixes reach into retained bytes.
            "suffix one byte into retained bytes": ("ab", "bd", ["abd"]),
            "suffix spanning the whole string": ("ab", "abd", ["abd"]),
            "suffix differing in retained bytes": ("ab", "cd", []),
            "prefix between two strings": ("abz", None, []),
            "prefix before every string": ("0", None, []),
            "prefix after every string": ("zzz", None, []),
            "empty prefix": ("", None, []),
        }
        for name, (prefix, suffix, expected) in cases.items():
            with self.subTest(name):
                self.assertEqual([s for _, s in section.affix(prefix, suffix)], expected)
        for local_id, text in section.affix("b", None):
            self.assertEqual(section.extract(local_id), text)

    def test_empty_section(self) -> None:
        self.assertEqual(make_section(TYPE_NUL, [], 16).affix("a", None), [])

    def test_stops_at_the_first_entry_past_the_run(self) -> None:
        # The fourth entry is corrupt (it retains 5 bytes of the 1-byte "d"). The run for "b"
        # ends at "d", so the search must stop there; the run for "d" has to read the corrupt entry.
        packed = b"a\x00\x80b\x00\x81b\x00\x80d\x00\x85e\x00"
        data = section_bytes(TYPE_NUL, packed, [0, len(packed)], 5, 16)
        section = PfcSection(_Reader(data), False)
        self.assertEqual(section.affix("b", None), [(2, "b"), (3, "bb")])
        with self.assertRaisesRegex(ValueError, "retains more bytes"):
            section.affix("d", None)

    def test_invalid_utf8_raises(self) -> None:
        section = make_section(TYPE_NUL, [b"ab", b"ab\xff", b"ac"], 2)
        with self.assertRaises(ValueError):
            section.affix("ab", None)


class HdtAffixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with open(path.join(HDT_FIXTURES, "synthetic.hdt"), "rb") as f:
            cls.hdt = PyHdt(f.read())
        triples = [(t.subject, t.predicate, t.object) for t in cls.hdt.triples()]
        cls.subjects = sorted({s for s, _, _ in triples})
        cls.predicates = sorted({p for _, p, _ in triples})
        cls.objects = sorted({o for _, _, o in triples})

    def check(self, found: list[str], terms: list[str], prefix: str, suffix: str | None) -> None:
        expected = [t for t in terms if t.startswith(prefix) and t.endswith(suffix or "")]
        self.assertTrue(expected, "the fixture should have matches")
        self.assertEqual(sorted(found), expected)

    def test_subjects(self) -> None:
        for prefix, suffix in (("http://example.org/item/", None), ("http://", "Type")):
            with self.subTest(prefix=prefix, suffix=suffix):
                found = list(self.hdt.subjects_with_affixes(prefix, suffix))
                self.check(found, self.subjects, prefix, suffix)

    def test_predicates(self) -> None:
        prefix = "http://example.org/vocab#"
        found = list(self.hdt.predicates_with_affixes(prefix))
        self.check(found, self.predicates, prefix, None)

    def test_objects(self) -> None:
        for prefix, suffix in (("http://example.org/item/", None), ('"', "@en")):
            with self.subTest(prefix=prefix, suffix=suffix):
                found = list(self.hdt.objects_with_affixes(prefix, suffix))
                self.check(found, self.objects, prefix, suffix)

    def test_empty_prefix_yields_nothing(self) -> None:
        self.assertEqual(list(self.hdt.subjects_with_affixes("")), [])


class Utf8NulAffixTests(unittest.TestCase):
    """The HDT-NG UTF-8 fixture holds strings containing U+0000 (length-prefixed sections)."""

    def test_subjects_with_nul_bearing_strings(self) -> None:
        with open(path.join(HDT_FIXTURES, "hdt-ng-utf8.hdt"), "rb") as f:
            hdt = PyHdt(f.read())
        got = list(hdt.subjects_with_affixes("http://example.org#"))
        self.assertEqual(len(got), 3)
        self.assertTrue(any("\x00d" in s for s in got))
        self.assertTrue(any("\x00ghi" in s for s in got))


if __name__ == "__main__":
    unittest.main()
