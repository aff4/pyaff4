#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""HDT generation: round trips, edge cases, and the agreed metadata spec."""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import re
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from pyhdt2_cython import PyHdt
from pyhdt2_cython.build import control_info, from_triples
from pyhdt2_cython.hdt import Hdt, _read_control_info, _Reader

TRICKY = [
    ("http://ex.org/s1", "http://ex.org/p", "http://ex.org/o1"),
    ("<http://ex.org/s1>", "<http://ex.org/p>", "<http://ex.org/o1>"),  # duplicate after cleaning
    ("http://ex.org/s2", "http://ex.org/p", '"hello"@en'),
    ("http://ex.org/s2", "http://ex.org/p", '"hello"'),
    ("http://ex.org/s2", "http://ex.org/q", '"42"^^<http://www.w3.org/2001/XMLSchema#integer>'),
    ("_:b0", "http://ex.org/p", "_:b1"),
    ("_:b1", "http://ex.org/p", "http://ex.org/s1"),
    ("http://ex.org/ü", "http://ex.org/p", '"naïve café — ☃"'),
    ("http://ex.org/s3", "http://ex.org/p", '"line\\nbreak and \\"quotes\\""'),
    ("http://ex.org/o1", "http://ex.org/p", "http://ex.org/s2"),
]

ISSUED = datetime(2026, 10, 7, 1, 2, 3, tzinfo=UTC)


def as_tuples(hdt: PyHdt) -> list[tuple[str, str, str]]:
    return [(t.subject, t.predicate, t.object) for t in hdt.triples()]


class FixedClock(unittest.TestCase):
    """Tests whose output must not depend on when they run: dc:issued is ISSUED."""

    def setUp(self) -> None:
        self.enterContext(mock.patch("pyhdt2_cython.build._utc_now", return_value=ISSUED))


class GenerationTests(FixedClock):
    def test_empty_graph_loads_and_queries(self) -> None:
        empty = PyHdt.from_triples([])
        self.assertEqual(as_tuples(empty), [])
        self.assertEqual(list(empty.triples_with_pattern(None, None, "http://ex.org/o")), [])
        self.assertEqual(list(empty.subjects_with_affixes("http://")), [])

    def test_duplicates_after_cleaning_collapse(self) -> None:
        self.assertEqual(len(as_tuples(PyHdt.from_triples(TRICKY))), len(TRICKY) - 1)

    def test_regenerating_from_read_triples_is_byte_identical(self) -> None:
        first = from_triples(TRICKY)
        again = from_triples(as_tuples(PyHdt(first)))
        self.assertEqual(again, first)

    def test_write_round_trips_and_reports_unwritable_paths(self) -> None:
        hdt = PyHdt.from_triples(TRICKY)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.hdt"
            hdt.write(str(path))
            self.assertEqual(as_tuples(PyHdt(path.read_bytes())), as_tuples(hdt))
            with self.assertRaises(ValueError):
                hdt.write(str(Path(tmp) / "missing-dir" / "out.hdt"))

    def test_unreadable_input_raises_value_error(self) -> None:
        for data in (b"", b"not an hdt file"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                PyHdt(data)

    def test_every_truncation_raises_value_error(self) -> None:
        data = from_triples(TRICKY)
        for n in range(len(data)):
            with self.subTest(length=n), self.assertRaises(ValueError):
                PyHdt(data[:n])


HDT = "http://purl.org/HDT/hdt#"
VOID = "http://rdfs.org/ns/void#"
DC = "http://purl.org/dc/terms/"
BASE = "urn:hdt:in-memory"
XSD_INTEGER = "<http://www.w3.org/2001/XMLSchema#integer>"


def header_of(data: bytes) -> str:
    r = _Reader(data)
    _read_control_info(r)
    _, _, props = _read_control_info(r)
    return bytes(r.take(int(props["length"]))).decode()


def control_info_body(data: bytes, ctype: int) -> bytes:
    """The bytes of the control info of type `ctype`, from its $HDT cookie to its final NUL."""
    start = data.index(b"$HDT" + bytes([ctype]))
    end = data.index(b"\0", data.index(b"\0", start) + 1)
    return data[start : end + 1]


def written_payloads(data: bytes) -> tuple[int, int]:
    """(dictionary payload, triples payload) in bytes, measured on the sections as read back."""
    hdt = Hdt(data)
    sections = (hdt.shared, hdt.subjects, hdt.predicates, hdt.objects)
    dictionary = sum(len(sec.packed) + len(sec.offsets.data) for sec in sections)
    triples = sum(len(x.data) for x in (hdt.bitmap_y, hdt.bitmap_z, hdt.y, hdt.z))
    return dictionary, triples


class ControlInformationTests(FixedClock):
    def test_global_has_the_software_version(self) -> None:
        version = importlib.metadata.version("pyaff4")
        expected = f"$HDT\x01<{HDT}HDTv1>\0Software=pyaff4/{version};\0".encode()
        self.assertEqual(control_info_body(from_triples(TRICKY), 1), expected)

    def test_dictionary_and_triples(self) -> None:
        data = from_triples(TRICKY)
        hdt = Hdt(data)
        n_terms = sum(
            section.num_strings
            for section in (hdt.shared, hdt.subjects, hdt.predicates, hdt.objects)
        )
        self.assertEqual(
            control_info_body(data, 3),
            f"$HDT\x03<{HDT}dictionaryFourPsfc>\0elements={n_terms};\0".encode(),
        )
        self.assertEqual(
            control_info_body(data, 4),
            f"$HDT\x04<{HDT}triplesBitmap>\0numTriples=9;order=1;\0".encode(),
        )

    def test_properties_are_sorted_and_checked(self) -> None:
        body = control_info(1, "f", {"b": "2", "a": "1"})
        self.assertIn(b"\0a=1;b=2;\0", body)
        for props in ({"Software": "x;y"}, {"Software": "x=y"}, {"a;b": "1"}):
            with self.subTest(props=props), self.assertRaises(ValueError):
                control_info(1, "f", props)


class HeaderTests(FixedClock):
    def test_header_lines(self) -> None:
        data = from_triples(TRICKY)
        size_strings, triples_size = written_payloads(data)
        rdf_type = "<http://www.w3.org/1999/02/22-rdf-syntax-ns#type>"
        expected = [
            f"<{BASE}> {rdf_type} <{HDT}Dataset> .",
            f"<{BASE}> {rdf_type} <{VOID}Dataset> .",
            f'<{BASE}> <{VOID}triples> "9" .',
            f'<{BASE}> <{VOID}properties> "2" .',
            f'<{BASE}> <{VOID}distinctSubjects> "7" .',
            f'<{BASE}> <{VOID}distinctObjects> "9" .',
            f"<{BASE}> <{HDT}formatInformation> _:format .",
            f"_:format <{HDT}dictionary> _:dictionary .",
            f"_:format <{HDT}triples> _:triples .",
            f"<{BASE}> <{HDT}statisticalInformation> _:statistics .",
            f"<{BASE}> <{HDT}publicationInformation> _:publicationInformation .",
            f"_:dictionary <{DC}format> <{HDT}dictionaryFourPsfc> .",
            f'_:dictionary <{HDT}dictionarynumSharedSubjectObject> "4" .',
            f'_:dictionary <{HDT}dictionarymapping> "1" .',
            f'_:dictionary <{HDT}dictionarysizeStrings> "{size_strings}" .',
            f'_:dictionary <{HDT}dictionaryblockSize> "16" .',
            f"_:triples <{DC}format> <{HDT}triplesBitmap> .",
            f'_:triples <{HDT}triplesnumTriples> "9" .',
            f'_:triples <{HDT}triplesOrder> "SPO" .',
            f'_:statistics <{HDT}hdtSize> "{size_strings + triples_size}" .',
            f'_:publicationInformation <{DC}issued> "2026-10-07T01:02:03Z" .',
        ]
        self.assertEqual(header_of(data).splitlines(), expected)
        self.assertTrue(header_of(data).endswith(" .\n"))

    def test_original_size_only_when_given(self) -> None:
        line = f'_:statistics <{HDT}originalSize> "123" .'
        self.assertNotIn("originalSize", header_of(from_triples(TRICKY)))
        lines = header_of(from_triples(TRICKY, original_size=123)).splitlines()
        self.assertEqual(lines[-3], line)
        with self.assertRaises(ValueError):
            from_triples(TRICKY, original_size=-1)

    def test_sizes_match_the_written_sections(self) -> None:
        big = [(f"http://ex.org/s{i}", f"http://ex.org/p{i % 5}", f'"{i}"') for i in range(3000)]
        for name, triples in (("tricky", TRICKY), ("big", big), ("empty", [])):
            with self.subTest(name):
                data = from_triples(triples)
                size_strings, triples_size = written_payloads(data)
                header = header_of(data)
                self.assertIn(f'dictionarysizeStrings> "{size_strings}" .', header)
                self.assertIn(f'hdtSize> "{size_strings + triples_size}" .', header)


class IssuedTimeTests(unittest.TestCase):
    def test_issued_is_utc_to_the_second(self) -> None:
        line = header_of(from_triples(TRICKY)).splitlines()[-1]
        self.assertRegex(
            line,
            rf"^_:publicationInformation <{re.escape(DC)}issued> "
            r'"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ" \.$',
        )


class SequenceAndBitmapTests(FixedClock):
    def test_widths_follow_the_largest_ids(self) -> None:
        many = [(f"http://ex.org/s{i}", "http://ex.org/p", f'"{i % 3}"') for i in range(2000)]
        objects_255 = [(f"http://ex.org/s{i}", f"http://ex.org/p{i}", f'"{i}"') for i in range(255)]
        cases = {"tricky": (TRICKY, 2, 4), "N >> O_max": (many, 1, 2), "255": (objects_255, 8, 8)}
        for name, (triples, y_bits, z_bits) in cases.items():
            with self.subTest(name):
                hdt = Hdt(from_triples(triples))
                self.assertEqual((hdt.y.bits, hdt.z.bits), (y_bits, z_bits))
                p_max = hdt.predicates.num_strings
                o_max = hdt.shared.num_strings + hdt.objects.num_strings
                self.assertEqual((y_bits, z_bits), (p_max.bit_length(), o_max.bit_length()))

    def test_bitmaps_have_one_bit_per_entry(self) -> None:
        hdt = Hdt(from_triples(TRICKY))
        self.assertEqual(hdt.bitmap_y.num_bits, hdt.y.entries)
        self.assertEqual(hdt.bitmap_z.num_bits, hdt.z.entries)

    def test_empty_graph(self) -> None:
        data = from_triples([])
        hdt = Hdt(data)
        self.assertEqual((hdt.y.bits, hdt.y.entries, hdt.z.bits, hdt.z.entries), (0, 0, 0, 0))
        for bitmap in (hdt.bitmap_y, hdt.bitmap_z):
            self.assertEqual((bitmap.num_bits, len(bitmap.data)), (0, 0))
        self.assertEqual(as_tuples(PyHdt(data)), [])


class PsfcTests(FixedClock):
    TYPED = [
        ("http://ex.org/s", "http://ex.org/p", f'"42"^^{XSD_INTEGER}'),
        ("http://ex.org/s", "http://ex.org/p", '"7"^^<http://ex.org/a>'),
        ("http://ex.org/s", "http://ex.org/p", '"plain"'),
        ("http://ex.org/s", "http://ex.org/p", '"tagged"@en'),
        ("http://ex.org/t", "http://ex.org/p", "http://ex.org/iri"),
    ]

    def stored_objects(self, data: bytes) -> list[str]:
        section = Hdt(data).objects
        return [section.pfc.extract(i) for i in range(1, section.num_strings + 1)]

    def test_typed_literals_are_stored_suffix_coded_in_sorted_order(self) -> None:
        data = from_triples(self.TYPED)
        stored = self.stored_objects(data)
        self.assertIn(f'^^{XSD_INTEGER}"42"', stored)
        self.assertIn('^^<http://ex.org/a>"7"', stored)
        self.assertIn('"plain"', stored)
        self.assertEqual([s.encode() for s in stored], sorted(s.encode() for s in stored))
        hdt = Hdt(data)
        for _, _, o in self.TYPED:
            with self.subTest(o=o):
                self.assertEqual(
                    stored[hdt.objects.locate(o) - 1].encode(), _stored_form(o).encode()
                )
                self.assertEqual([t[2] for t in hdt.triples_with_pattern(None, None, o)], [o])

    def test_psfc_false_writes_the_plain_layout(self) -> None:
        data = from_triples(self.TYPED, psfc=False)
        self.assertIn(f'"42"^^{XSD_INTEGER}', self.stored_objects(data))
        self.assertFalse(Hdt(data).objects.suffix_coded)
        self.assertTrue(
            control_info_body(data, 3).startswith(f"$HDT\x03<{HDT}dictionaryFour>\0".encode())
        )
        self.assertIn(f"<{DC}format> <{HDT}dictionaryFour> .", header_of(data))
        self.assertEqual(sorted(as_tuples(PyHdt(data))), sorted(self.TYPED))

    def test_escaped_separator_in_untyped_literals_round_trips(self) -> None:
        triples = [
            ("http://ex.org/s", "http://ex.org/p", '"a\\"^^b"'),
            ("http://ex.org/s", "http://ex.org/p", '"a\\"^^b"@en'),
            ("http://ex.org/s", "http://ex.org/p", '"x\\"^^<http://ex.org/d>\\" tail"'),
        ]
        data = from_triples(triples)
        self.assertEqual(sorted(as_tuples(PyHdt(data))), sorted(triples))
        self.assertEqual(sorted(self.stored_objects(data)), sorted(o for _, _, o in triples))
        hdt = PyHdt(data)
        for _, _, o in triples:
            with self.subTest(o=o):
                self.assertEqual([t.object for t in hdt.triples_with_pattern(None, None, o)], [o])


def _stored_form(term: str) -> str:
    """How a suffix-coded objects section stores `term`, written independently of the writer."""
    if term.startswith('"') and term.endswith(">"):
        split = term.rindex('"^^') + 1
        return term[split:] + term[:split]
    return term


if __name__ == "__main__":
    unittest.main()
