#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Front-coded dictionary sections (types 2, 7, 8) and VBytes: round trips, lookups, bad input."""

from __future__ import annotations

import random
import unittest

import crc32c
import numpy as np

from pyhdt2_cython import _kernels as K
from pyhdt2_cython.build import _pack_sorted, encode_sequence, encode_vbyte
from pyhdt2_cython.hdt import HdtFormatError, PfcSection, _crc8_smbus, _Reader

TYPE_NUL, TYPE_LEN_NUL, TYPE_LEN = 2, 7, 8


def shared_prefix(a: bytes, b: bytes) -> int:
    n = 0
    while n < min(len(a), len(b)) and a[n] == b[n]:
        n += 1
    return n


def encode_type8(terms: list[bytes], block: int) -> tuple[bytes, list[int]]:
    """The packed strings and block offsets K.pfc_encode, the code under test, writes."""
    packed = _pack_sorted(terms)
    out = np.zeros(sum(map(len, terms)) + 10 * len(terms) + 1, dtype=np.uint8)
    offsets = np.zeros(len(terms) // block + 2, dtype=np.uint64)
    used = K.pfc_encode(
        packed.data,
        memoryview(packed.offsets),
        memoryview(packed.order),
        block,
        memoryview(out),
        memoryview(offsets),
    )
    n_offsets = (len(terms) + block - 1) // block + 1
    return out[:used].tobytes(), offsets[:n_offsets].tolist()


def encode_independently(
    terms: list[bytes], block: int, stype: int, whole_chars: bool = False
) -> tuple[bytes, list[int]]:
    """Any section type, written independently of the code under test. Retained counts are
    bytewise or, with whole_chars, cover whole UTF-8 characters
    only."""
    out, offsets = bytearray(), []
    for i, t in enumerate(terms):
        k = 0
        if i % block == 0:
            offsets.append(len(out))
        else:
            k = shared_prefix(terms[i - 1], t)
            while whole_chars and k > 0 and t[k] & 0xC0 == 0x80:
                k -= 1
            out += encode_vbyte(k)
        if stype != TYPE_NUL:
            out += encode_vbyte(len(t) - k)
        out += t[k:]
        if stype != TYPE_LEN:
            out.append(0)
    if terms:
        offsets.append(len(out))
    return bytes(out), offsets


def section_bytes(stype: int, packed: bytes, offsets: list[int], n: int, block: int) -> bytes:
    header = bytes([stype]) + encode_vbyte(n) + encode_vbyte(len(packed)) + encode_vbyte(block)
    seq = encode_sequence(np.array(offsets, dtype=np.uint64))
    crc = crc32c.crc32c(packed).to_bytes(4, "little")
    return header + bytes([_crc8_smbus(header)]) + seq + packed + crc


def make_section(stype: int, terms: list[bytes], block: int) -> PfcSection:
    """A section of `stype`: type 8 as the builder writes it, types 2 and 7 (read only) as
    encode_independently writes them."""
    if stype == TYPE_LEN:
        packed, offsets = encode_type8(terms, block)
    else:
        packed, offsets = encode_independently(terms, block, stype, whole_chars=True)
    return PfcSection(_Reader(section_bytes(stype, packed, offsets, len(terms), block)), False)


def sample_terms(n: int, seed: int) -> list[bytes]:
    rng = random.Random(seed)
    stems = ["http://ex.org/", "http://ex.org/a/", "_:b", '"lit', "urn:x:", "http://é.org/"]
    tails = ["", "a", "ab", "é", "ê", "€", "😀", "z" * 40, "ࠀ", "ࠁ"]
    terms = {
        (rng.choice(stems) + "".join(rng.choices(tails, k=rng.randrange(4))) + str(i)).encode()
        for i in range(n)
    }
    # Neighbours that share the lead byte of differing multi-byte characters (é vs ê).
    terms |= {"x/é".encode(), "x/ê".encode(), "x/ࠀbc".encode(), "x/ࠁ".encode()}
    return sorted(terms)


def absent_probes(terms: list[bytes]) -> list[bytes]:
    present = set(terms)
    probes = [b"", b"\x01", b"\xff\xff", terms[0][:-1], terms[-1] + b"z"]
    for t in terms[::7]:
        probes += [t + b"\x00", t[:-1], t + b"!", t[:-1] + bytes([t[-1] + 1 if t[-1] < 255 else 0])]
    return [p for p in probes if p not in present]


class RoundTripTests(unittest.TestCase):
    def test_every_type_and_block_size(self) -> None:
        terms = sample_terms(600, seed=5)
        for stype in (TYPE_NUL, TYPE_LEN_NUL, TYPE_LEN):
            for block in (1, 2, 3, 16, 64, 1000):
                with self.subTest(type=stype, block=block):
                    section = make_section(stype, terms, block)
                    texts = [t.decode() for t in terms]
                    self.assertEqual([section.extract(i) for i in range(1, len(terms) + 1)], texts)
                    self.assertEqual(
                        [section.locate(t) for t in texts], list(range(1, len(terms) + 1))
                    )
                    for probe in absent_probes(terms):
                        self.assertEqual(section.pfc.locate(probe), 0, probe)

    def test_single_term_and_empty_string_first(self) -> None:
        for stype in (TYPE_NUL, TYPE_LEN_NUL, TYPE_LEN):
            with self.subTest(type=stype):
                one = make_section(stype, [b"only"], 16)
                self.assertEqual(
                    (one.extract(1), one.locate("only"), one.locate("x")), ("only", 1, 0)
                )
                with_empty = make_section(stype, [b"", b"a", b"ab"], 2)
                self.assertEqual([with_empty.extract(i) for i in (1, 2, 3)], ["", "a", "ab"])
                self.assertEqual([with_empty.locate(s) for s in ("", "a", "ab")], [1, 2, 3])

    def test_empty_section(self) -> None:
        section = make_section(TYPE_NUL, [], 16)
        self.assertEqual(section.locate("anything"), 0)

    def test_multi_byte_vbytes(self) -> None:
        # Retained counts and string lengths above 127 need two- and three-byte VBytes.
        stem = b"http://ex.org/" + b"p" * 300
        terms = [stem + b"a" * 20000, stem + b"b", stem + b"b" + b"c" * 200, stem + b"d" * 130]
        for stype in (TYPE_NUL, TYPE_LEN_NUL, TYPE_LEN):
            with self.subTest(type=stype):
                section = make_section(stype, terms, 16)
                texts = [t.decode() for t in terms]
                self.assertEqual([section.extract(i) for i in range(1, 5)], texts)
                self.assertEqual([section.locate(t) for t in texts], [1, 2, 3, 4])

    def test_type8_bytes_follow_the_length_prefixed_layout(self) -> None:
        # Block 0: "abc" whole (length 3), then "abd" keeping 2 bytes and adding 1. Block 1: "b".
        packed, offsets = encode_type8([b"abc", b"abd", b"b"], 2)
        self.assertEqual(packed, b"\x83abc\x82\x81d\x81b")
        self.assertEqual(offsets, [0, 7, 9])

    def test_terms_containing_nul_round_trip(self) -> None:
        # NUL sorts below every other byte: "a" < "a\0" < "a\0b" < "ab", within and across blocks.
        terms = [b"", b"\x00", b"a", b"a\x00", b"a\x00b", b"a\x00b\x00", b"ab", b"b\x00\x00c"]
        for block in (1, 2, 3, 16):
            with self.subTest(block=block):
                section = make_section(TYPE_LEN, terms, block)
                texts = [t.decode() for t in terms]
                self.assertEqual([section.extract(i) for i in range(1, 9)], texts)
                self.assertEqual([section.locate(t) for t in texts], list(range(1, 9)))
                self.assertEqual(section.locate("a\x00a"), 0)
        packed, _ = encode_type8([b"a\x00b", b"a\x00c"], 16)
        self.assertEqual(packed, b"\x83a\x00b\x82\x81c")

    def test_shared_count_covers_whole_characters(self) -> None:
        cases = {
            # é is C3 A9 and ê is C3 AA: they share a byte, but no whole character.
            "two-byte": (["é", "ê"], b"\x82\xc3\xa9\x80\x82\xc3\xaa"),
            # U+0800 is E0 A0 80 and U+0801 is E0 A0 81.
            "three-byte": (["a\u0800", "a\u0801"], b"\x84a\xe0\xa0\x80\x81\x83\xe0\xa0\x81"),
            # A whole shared é is kept.
            "whole character": (["aé1", "aé2"], b"\x84a\xc3\xa91\x83\x812"),
        }
        for name, (terms, expected) in cases.items():
            with self.subTest(name):
                packed, _ = encode_type8([t.encode() for t in terms], 16)
                self.assertEqual(packed, expected)
                section = make_section(TYPE_LEN, [t.encode() for t in terms], 16)
                self.assertEqual([section.extract(i) for i in (1, 2)], terms)

    def test_empty_section_has_one_offset(self) -> None:
        self.assertEqual(encode_type8([], 16), (b"", [0]))

    def test_locate_after_a_partly_shared_character(self) -> None:
        # "x/ê" follows "x/é" after a block's first string. Writers count its retained bytes in
        # whole characters or bytewise (3); both must be found.
        terms = ["a", "x/é", "x/ê", "x/ê2"]
        layouts = {
            (TYPE_NUL, "whole characters"): b"a\x00\x80x/\xc3\xa9\x00\x82\xc3\xaa\x00\x842\x00",
            (TYPE_NUL, "bytewise"): b"a\x00\x80x/\xc3\xa9\x00\x83\xaa\x00\x842\x00",
            (TYPE_LEN, "whole characters"): b"\x81a\x80\x84x/\xc3\xa9\x82\x82\xc3\xaa\x84\x812",
            (TYPE_LEN, "bytewise"): b"\x81a\x80\x84x/\xc3\xa9\x83\x81\xaa\x84\x812",
        }
        written = encode_type8([t.encode() for t in terms], 16)[0]
        self.assertEqual(written, layouts[TYPE_LEN, "whole characters"])
        for (stype, name), packed in layouts.items():
            with self.subTest(type=stype, counted=name):
                data = section_bytes(stype, packed, [0, len(packed)], len(terms), 16)
                section = PfcSection(_Reader(data), False)
                self.assertEqual([section.extract(i) for i in range(1, 5)], terms)
                self.assertEqual([section.locate(t) for t in terms], [1, 2, 3, 4])
                self.assertEqual(section.locate("x/ë"), 0)

    def test_misses_inside_a_block(self) -> None:
        # Needles that fall between entries: a prefix of an entry, an extension of one, and
        # characters sharing a lead byte with their neighbours (è C3 A8 < é C3 A9 < ê C3 AA).
        terms = ["a", "abc", "abd", "x/é", "x/ê", "x/ê2", "y"]
        misses = ["ab", "abca", "abcz", "abe", "x/è", "x/ê1", "x/ê3", "x/ë", "x", "z"]
        for stype in (TYPE_NUL, TYPE_LEN_NUL, TYPE_LEN):
            with self.subTest(type=stype):
                section = make_section(stype, [t.encode() for t in terms], 16)
                self.assertEqual([section.locate(t) for t in misses], [0] * len(misses))
                self.assertEqual([section.locate(t) for t in terms], list(range(1, len(terms) + 1)))

    def test_miss_stops_at_the_first_greater_entry(self) -> None:
        # The fourth entry is corrupt (it retains 5 bytes of the 1-byte "d"). A miss that sorts
        # before "d" must stop there; one that sorts after it has to read the corrupt entry.
        packed = b"a\x00\x80b\x00\x80d\x00\x85e\x00"
        data = section_bytes(TYPE_NUL, packed, [0, len(packed)], 4, 16)
        section = PfcSection(_Reader(data), False)
        self.assertEqual(
            (section.locate("c"), section.locate("b"), section.locate("bb")), (0, 2, 0)
        )
        with self.assertRaisesRegex(ValueError, "retains more bytes"):
            section.locate("dd")


# Characters whose UTF-8 forms share lead bytes: é C3 A9 / ê C3 AA, U+0800 E0 A0 80 / U+0801
# E0 A0 81, 😀 F0 9F 98 80 / 😁 F0 9F 98 81 / 🙀 F0 9F 99 80.
ALPHABET = ["a", "b", "z", "é", "ê", "ࠀ", "ࠁ", "€", "😀", "😁", "🙀"]


def random_terms(rng: random.Random, with_nul: bool) -> list[bytes]:
    """A sorted set of distinct strings that share many prefixes, possibly including ""."""
    alphabet = ALPHABET + ["\x00"] if with_nul else ALPHABET
    stems = ["", "http://ex.org/", "http://ex.org/é"]
    terms = set()
    for _ in range(rng.randint(1, 80)):
        tail = "".join(rng.choices(alphabet, k=rng.randrange(7)))
        terms.add((rng.choice(stems) + tail).encode())
    return sorted(terms)


def probes_around(terms: list[bytes]) -> list[bytes]:
    """Strings near the present ones: before the first, between neighbours, after the last, a
    proper prefix, an extension, and a one-byte change at the end of each."""
    probes = [b"", terms[0][:-1], terms[-1] + b"\x01", b"\xff"]
    for a, b in zip(terms, terms[1:], strict=False):
        probes.append(a + b"\x00")
        probes.append(b[: shared_prefix(a, b) + 1] + b"\x00")
    for t in terms:
        probes += [t[: len(t) // 2], t + b"a", t + b"\xc3"]
        if t:
            probes += [t[:-1] + bytes([(t[-1] + 1) % 256]), t[:-1] + bytes([(t[-1] - 1) % 256])]
    present = set(terms)
    return [p for p in probes if p not in present]


class RandomisedEquivalenceTests(unittest.TestCase):
    """extract, locate and affix against the input strings, for every layout and both ways
    writers count retained bytes."""

    def test_random_sections(self) -> None:
        for seed in range(12):
            rng = random.Random(seed)
            for stype in (TYPE_NUL, TYPE_LEN_NUL, TYPE_LEN):
                terms = random_terms(rng, with_nul=stype != TYPE_NUL)
                probes = probes_around(terms)
                for block in (1, 2, 16, 32):
                    for whole_chars in (False, True):
                        with self.subTest(
                            seed=seed, type=stype, block=block, whole_chars=whole_chars
                        ):
                            self.check(terms, probes, block, stype, whole_chars)

    def check(self, terms, probes, block: int, stype: int, whole_chars: bool) -> None:
        packed, offsets = encode_independently(terms, block, stype, whole_chars)
        if stype == TYPE_LEN and whole_chars:
            self.assertEqual(encode_type8(terms, block), (packed, offsets), "builder layout")
        data = section_bytes(stype, packed, offsets, len(terms), block)
        pfc = PfcSection(_Reader(data), False).pfc
        ids = range(1, len(terms) + 1)
        self.assertEqual([pfc.extract(i) for i in ids], [t.decode() for t in terms])
        self.assertEqual([pfc.locate(t) for t in terms], list(ids))
        self.assertEqual([p for p in probes if pfc.locate(p) != 0], [])
        texts = [t.decode() for t in terms]
        for prefix in {p[:3] for p in probes + terms if p[:3]}:
            for suffix in (b"", terms[0][-2:], terms[-1][-1:], "é".encode()[1:], b"http"):
                expected = [
                    (i, text)
                    for i, (t, text) in enumerate(zip(terms, texts, strict=True), 1)
                    if t.startswith(prefix) and t.endswith(suffix)
                ]
                self.assertEqual(pfc.affix(prefix, suffix), expected, (prefix, suffix))


class VByteTests(unittest.TestCase):
    VECTORS = [
        (0, b"\x80"),
        (1, b"\x81"),
        (127, b"\xff"),
        (128, b"\x00\x81"),
        (16383, b"\x7f\xff"),
        (16384, b"\x00\x00\x81"),
        (2**32, b"\x00\x00\x00\x00\x90"),
        (2**64 - 1, b"\x7f" * 9 + b"\x81"),
    ]

    def test_known_encodings(self) -> None:
        for value, encoded in self.VECTORS:
            with self.subTest(value=value):
                self.assertEqual(encode_vbyte(value), encoded)
                got, raw = _Reader(encoded + b"tail").vbyte()
                self.assertEqual((got, raw), (value, encoded))

    def test_negative_values_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            encode_vbyte(-1)

    def test_unterminated_or_overlong_vbytes_are_rejected(self) -> None:
        for data in (b"", b"\x00\x00", b"\x00" * 10 + b"\x81"):
            with self.subTest(data=data), self.assertRaises(HdtFormatError):
                _Reader(data).vbyte()


class CorruptSectionTests(unittest.TestCase):
    def section(self, stype: int, packed: bytes, offsets: list[int], n: int, block: int):
        return PfcSection(_Reader(section_bytes(stype, packed, offsets, n, block)), False)

    def test_retained_count_longer_than_previous_string(self) -> None:
        # Second entry claims to keep 9 bytes of the 3-byte "abc".
        bad = self.section(TYPE_NUL, b"abc\x00\x89d\x00", [0, 7], 2, 16)
        self.assertEqual(bad.extract(1), "abc")
        with self.assertRaisesRegex(ValueError, "retains more bytes"):
            bad.extract(2)
        with self.assertRaisesRegex(ValueError, "retains more bytes"):
            bad.locate("abd")

    def test_huge_retained_count_does_not_allocate(self) -> None:
        # VByte 7F 7F 7F 7F 8F = 2^32 - 1: refused before sizing any buffer.
        bad = self.section(TYPE_NUL, b"a\x00\x7f\x7f\x7f\x7f\x8fz\x00", [0, 9], 2, 16)
        with self.assertRaisesRegex(ValueError, "retains more bytes"):
            bad.extract(2)

    def test_truncated_structures(self) -> None:
        cases = {
            "no NUL": (TYPE_NUL, b"abc", [0, 3], 1),
            "VByte runs off the block": (TYPE_NUL, b"a\x00\x01\x02", [0, 4], 2),
            "VByte longer than 5 bytes": (TYPE_NUL, b"a\x00" + b"\x00" * 6 + b"\x81", [0, 9], 2),
            "length past the block": (TYPE_LEN, b"\x89ab", [0, 3], 1),
        }
        for name, (stype, packed, offsets, n) in cases.items():
            with self.subTest(name), self.assertRaisesRegex(ValueError, "malformed"):
                self.section(stype, packed, offsets, n, 16).extract(n)

    def test_ids_out_of_range(self) -> None:
        section = make_section(TYPE_NUL, [b"a", b"b"], 16)
        for bad_id in (0, 3, -1):
            with self.subTest(id=bad_id), self.assertRaises(IndexError):
                section.pfc.extract(bad_id)


class EncoderInputTests(unittest.TestCase):
    def test_unsorted_or_duplicate_terms_are_rejected(self) -> None:
        for terms in ([b"b", b"a"], [b"a", b"a"], [b"ab", b"a"]):
            with self.subTest(terms=terms), self.assertRaisesRegex(ValueError, "byte order"):
                encode_type8(terms, 16)


if __name__ == "__main__":
    unittest.main()
