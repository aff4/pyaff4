#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""HDT reader. Hot loops live in `pyhdt2_cython._kernels` (Cython pure-Python mode)."""

from __future__ import annotations

import crc32c
import numpy as np

from pyhdt2_cython import _kernels as K

U64 = np.uint64

# DictionarySections of [HDT-BF §4] we support. We skip the reserved sections (which shadow
# experimental section types defined by HDT-CPP) and allocate two new sections types to support
# UTF-8 containing NUL's
#
# [HDT-BF] HDT Binary Format (draft 2015-03-07), https://www.rdfhdt.org/hdt-binary-format/
_SECTION_ENCODINGS = {
    # HDT v1 NUL terminated ASCII String
    2: K.ENC_NUL_TERMINATED,
    # Length prefixed (VByte-encoded) UTF-8 encoded string with trailing NUL
    7: K.ENC_LENGTH_PREFIXED_NUL,
    # Length prefixed (VByte-encoded) UTF-8 encoded string
    8: K.ENC_LENGTH_PREFIXED,
}


class HdtFormatError(ValueError):
    """The input is not a supported, intact HDT file."""


# ---------------------------------------------------------------------------
# Small CRCs (headers only) and VByte
# ---------------------------------------------------------------------------


# the full CRC-8 parameters are CRC-8/SMBUS
# (poly 0x07, init 0, refin/refout=false, xorout 0)
def _crc8_smbus(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def _crc16_arc(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


class _Reader:
    """Cursor over the HDT bytes; slices are zero-copy memoryviews."""

    def __init__(self, data: bytes) -> None:
        if not isinstance(data, bytes | bytearray):
            data = bytes(data)
        self.data = data
        self.buf = memoryview(data)
        self.pos = 0

    def take(self, n: int) -> memoryview:
        if self.pos + n > len(self.buf):
            raise HdtFormatError(f"truncated HDT: need {n} bytes at offset {self.pos}")
        out = self.buf[self.pos : self.pos + n]
        self.pos += n
        return out

    def byte(self) -> int:
        return self.take(1)[0]

    def until_nul(self) -> bytes:
        end = self._find_nul()
        out = bytes(self.buf[self.pos : end])
        self.pos = end + 1
        return out

    def _find_nul(self) -> int:
        end = self.data.find(b"\0", self.pos)
        if end < 0:
            raise HdtFormatError(f"truncated HDT: no NUL terminator after offset {self.pos}")
        return end

    # VByte of [HDT-BF] (inverted-continuation varint — non-final bytes have MSB
    # clear, the terminator has MSB set)
    def vbyte(self) -> tuple[int, bytes]:
        """The VByte at the cursor (at most 10 bytes), and its bytes."""
        start = self.pos
        value = 0
        for shift in range(0, 64, 7):
            b = self.byte()
            value |= (b & 0x7F) << shift
            if b & 0x80:
                return value & 0xFFFFFFFFFFFFFFFF, bytes(self.buf[start : self.pos])
        raise HdtFormatError(f"malformed VByte at offset {start}: no terminator in 10 bytes")


def _check_crc32c(body: memoryview, stored: memoryview, what: str) -> None:
    got = crc32c.crc32c(body)
    want = int.from_bytes(stored, "little")
    if got != want:
        raise HdtFormatError(
            f"{what}: CRC-32C mismatch (computed {got:#010x}, stored {want:#010x})"
        )


def _read_control_info(r: _Reader) -> tuple[int, str, dict[str, str]]:
    start = r.pos
    if bytes(r.take(4)) != b"$HDT":
        raise HdtFormatError(f"missing $HDT cookie at offset {start}")
    ctype = r.byte()
    fmt = r.until_nul().decode()
    props_raw = r.until_nul().decode()
    body = bytes(r.buf[start : r.pos])
    stored = int.from_bytes(r.take(2), "little")
    if _crc16_arc(body) != stored:
        raise HdtFormatError(f"control info at offset {start}: CRC-16 mismatch")
    props = dict(item.split("=", 1) for item in props_raw.split(";") if "=" in item)
    return ctype, fmt, props


def _words_from_body(body: memoryview) -> np.ndarray:
    """Little-endian u64 words from a byte body, padded with one extra zero word (a temporary)."""
    n_words = (len(body) + 7) // 8
    out = np.zeros(n_words + 1, dtype=U64)
    out.view(np.uint8)[: len(body)] = np.frombuffer(body, dtype=np.uint8)
    return out


def _unpack(data: memoryview, bits: int, entries: int, dtype=U64) -> np.ndarray:
    """Every entry of a packed sequence as an array: a temporary, for building indexes and
    writing sidecars. Queries read entries in place with K.seq_get instead."""
    if entries == 0:
        return np.zeros(0, dtype=dtype)
    words = _words_from_body(data)
    pos = np.arange(entries, dtype=U64) * U64(bits)
    wi = (pos >> U64(6)).astype(np.intp)
    off = pos & U64(63)
    lo = words[wi] >> off
    spill = (off + U64(bits)) > U64(64)
    hi = words[wi + 1] << ((U64(64) - off) & U64(63))
    v = lo | np.where(spill, hi, U64(0))
    mask = U64((1 << bits) - 1) if bits < 64 else U64(0xFFFFFFFFFFFFFFFF)
    return (v & mask).astype(dtype)


def _superblock_counts(data) -> np.ndarray:
    """cum[b] = set bits before 512-bit superblock b, for rank/select over a bitmap's bytes."""
    raw = np.frombuffer(data, dtype=np.uint8)
    n_super = (len(raw) + 63) // 64
    cum = np.zeros(n_super + 1, dtype=U64)
    if n_super:
        counts = np.add.reduceat(np.bitwise_count(raw), np.arange(0, len(raw), 64), dtype=U64)
        np.cumsum(counts, out=cum[1:])
    return cum


# ---------------------------------------------------------------------------
# Containers, read in place: `data` is a memoryview into the HDT or sidecar bytes.
# ---------------------------------------------------------------------------


# Sequence section (HDT Log64)
#
# The ArrayY/ArrayZ format of [HDT-BF §5] with format `0x01` (Log64).  [HDT-BF] omits
# the bitsPerEntry byte and is vague about the data area (exact bit positions and byte length),
# so the full layout is:
#    u8    type          = 0x01 (SEQ_LOG64)
#    u8    bitsPerEntry  1..64
#    VByte countEntries  == entries
#    u8    headerCRC8    CRC-8 over [type, bitsPerEntry, countEntries]
#    bytes data          ceil(bitsPerEntry * countEntries / 8) bytes, little-endian;
#                        value i occupies bits [i*bitsPerEntry, (i+1)*bitsPerEntry)
#    u32   dataCRC32C    little-endian, over the data bytes
#
# [HDT-BF] HDT Binary Format (draft 2015-03-07), https://www.rdfhdt.org/hdt-binary-format/
class Sequence:
    """HDT LogArray: packed little-endian integers of fixed width."""

    def __init__(self, r: _Reader) -> None:
        start = r.pos
        if r.byte() != 1:
            raise HdtFormatError(f"sequence at offset {start}: unsupported type")
        self.bits = r.byte()
        if self.bits > 64:
            raise HdtFormatError(f"sequence at offset {start}: {self.bits}-bit entries")
        self.entries, _ = r.vbyte()
        header = bytes(r.buf[start : r.pos])
        if _crc8_smbus(header) != r.byte():
            raise HdtFormatError(f"sequence at offset {start}: CRC-8 mismatch")
        # The body is ceil(bits * entries / 8) bytes.
        self.data = r.take((self.bits * self.entries + 7) // 8)
        _check_crc32c(self.data, r.take(4), f"sequence at offset {start}")

    def get(self, i: int) -> int:
        return K.seq_get(self.data, self.bits, i)

    def unpack(self, dtype=U64) -> np.ndarray:
        return _unpack(self.data, self.bits, self.entries, dtype)


# The BitmapY/BitmapZ format of [HDT-BF §5] with format `0x01` and `numBits == entries`;
# data is `ceil(numBits/8)` bytes, bit i is byte `i>>3` bit `i&7`.
#
# [HDT-BF]** HDT Binary Format (draft 2015-03-07), https://www.rdfhdt.org/hdt-binary-format/
class Bitmap:
    """Bit vector with rank1/select1 via one cumulative count per 512 bits."""

    def __init__(self, data, num_bits: int) -> None:
        self.data = data
        self.num_bits = num_bits
        self.cum = _superblock_counts(data)

    @classmethod
    def read(cls, r: _Reader) -> Bitmap:
        start = r.pos
        if r.byte() != 1:
            raise HdtFormatError(f"bitmap at offset {start}: unsupported type")
        num_bits, _ = r.vbyte()
        header = bytes(r.buf[start : r.pos])
        if _crc8_smbus(header) != r.byte():
            raise HdtFormatError(f"bitmap at offset {start}: CRC-8 mismatch")
        # The body is ceil(num_bits / 8) bytes.
        body = r.take((num_bits + 7) // 8)
        _check_crc32c(body, r.take(4), f"bitmap at offset {start}")
        return cls(body, num_bits)

    def rank1(self, i: int) -> int:
        return K.bm_rank1(self.data, self.cum, i)

    def select1(self, k: int) -> int:
        return K.bm_select1(self.data, self.cum, k)


# The DictionarySectionPlainFrontCoding format of [HDT-BF §4], extended to support NUL's
# HDT v1 relies on NULL terminators for determining the end of strings (and hence length),
# which fails for valid UTF-8 strings containing the Unicode NUL code point.
#
# This implementation includes support for reading and writing HDT serializations which include
# the full range of UTF-8, by defining a new DictionarySection type. The newly defined
# PlainFrontCodingUtf8 = 8 dictionary section reuses the design of the existing PlainFrontCoding
# DictionarySection, instead employing a length-prepended string encoding, per the following
# structure:
#   <Buffer of Blocks>
#   <VByte size of following string in bytes>
#   <First String of Block>
#   <VByte count of Common prefix characters> <VByte size of following string in bytes>
#       <Suffix String>
#   … as many times as necessary to fit "BlockSize" strings.
#   <CRC32 of Buffer of Blocks>
#
# [HDT-BF]** HDT Binary Format (draft 2015-03-07), https://www.rdfhdt.org/hdt-binary-format/


class PfcSection:
    """Plain front-coded dictionary section."""

    def __init__(self, r: _Reader, suffix_coded: bool) -> None:
        start = r.pos
        stype = r.byte()
        if stype not in _SECTION_ENCODINGS:
            raise HdtFormatError(f"dictionary section at offset {start}: unsupported type {stype}")
        self.enc = _SECTION_ENCODINGS[stype]
        self.num_strings, _ = r.vbyte()
        packed_len, _ = r.vbyte()
        self.block_size, _ = r.vbyte()
        header = bytes(r.buf[start : r.pos])
        if _crc8_smbus(header) != r.byte():
            raise HdtFormatError(f"dictionary section at offset {start}: CRC-8 mismatch")
        self.offsets = Sequence(r)
        self.packed = r.take(packed_len)
        _check_crc32c(self.packed, r.take(4), f"dictionary section at offset {start}")
        self.suffix_coded = suffix_coded
        self.pfc = K.Pfc(
            self.packed,
            self.offsets.data,
            self.offsets.bits,
            self.offsets.entries,
            self.block_size,
            self.enc,
            self.num_strings,
        )
        if not suffix_coded:
            self.extract = self.pfc.extract

    def extract(self, local_id: int) -> str:
        return K.psfc_decode_if_literal(self.pfc.extract(local_id))

    def locate(self, term: str) -> int:
        if self.num_strings == 0:
            return 0
        if self.suffix_coded:
            term = K.psfc_encode_if_literal(term)
        return self.pfc.locate(term.encode("utf-8"))

    def affix(self, prefix: str, suffix: str | None) -> list[tuple[int, str]]:
        """(local_id, stored string) for entries that start with prefix and end with suffix."""
        return self.pfc.affix(prefix.encode("utf-8"), (suffix or "").encode("utf-8"))


# ---------------------------------------------------------------------------
# The object index
#
# The OP-S index of HDT-FoQ [MAF12 §4.3], stored in the on-disk layout of
# [hdt-rs] v0.7.3 OpIndex: a positions Sequence plus an object-boundary Bitmap,
# both in the standard HDT sub-section formats [HDT-BF §5]
# opPositions is SoP and boundaries is BoP of [MAF12 §4.3]: a map per object of the
# predicate-subject pairs that have that object, sorted by predicate.
#
# Let entries = the triple count.
#
# opPositions[k] (0 <= k < entries): is a Y-level position pos_y — the 0-based
# index of a (subject,predicate) pair in the BitmapTriples predicate sequence. Runs are
# ordered by object 1..maxObject. From pos_y a reader recovers:
#   predicate = Ysequence[pos_y];
#   subject = 1 + rank1(Ypredicate-bitmap, pos_y-1).
#
# boundaries (HDT plain bitmap): Unlike BitmapY/BitmapZ of [HDT-BF §5], where a 1-bit marks
# the *last* sibling, here a 1-bit marks the *first* entry of a run.
# Every id `1..maxObject` occurs at least once as an object, — so the o-th set bit starts
# object `o`.
#  find(o) (start of object o's run): boundaries.select1_0based(o-1) (0-based select:
#    position of the o-th set bit). In this repo's 1-based select1, that
#    is select1(o).
#  last(o) (inclusive end) = select1_0based(o) - 1, or entries - 1 if `o` is the
#  last object. Equivalently the exclusive end is select1(o+1) (1-based) or entries.
#
# [MAF12]** M. A. Martínez-Prieto, M. Arias, J. D. Fernández. *Exchange and Consumption
#    of Huge RDF Data.* ESWC 2012, pp. 437–452.
# [HDT-INT]** HDT Internals, https://www.rdfhdt.org/hdt-internals/
def read_opidx_sidecar(data: bytes) -> tuple[int, int, Sequence, Bitmap]:
    """Parse and verify a .opidx sidecar; its positions and boundary bitmap are read in place.

    Returns (entries, max_object, positions, boundary bitmap). The bitmap must mark exactly one
    run start per object.
    """
    r = _Reader(data)
    if r.byte() != 0x03:
        raise HdtFormatError(".opidx: unexpected type byte")
    entries, _ = r.vbyte()
    max_object, _ = r.vbyte()
    if _crc8_smbus(bytes(r.buf[: r.pos])) != r.byte():
        raise HdtFormatError(".opidx: header CRC-8 mismatch")
    seq = Sequence(r)
    bitmap = Bitmap.read(r)
    if seq.entries != entries or bitmap.num_bits != entries:
        raise HdtFormatError(
            f".opidx: {seq.entries} positions and {bitmap.num_bits} boundary bits for {entries}"
        )
    run_starts = int(bitmap.cum[-1])
    if run_starts != max_object:
        raise HdtFormatError(
            f".opidx: {run_starts} object run starts marked for max_object={max_object}"
        )
    return entries, max_object, seq, bitmap


# ---------------------------------------------------------------------------
# HDT
# ---------------------------------------------------------------------------


class Hdt:
    """An HDT graph read in place from bytes, optionally with .opidx sidecar bytes.

    Nothing is unpacked: dictionary sections, bitmaps, the Y and Z sequences and the sidecar are
    read where they lie. Without a sidecar the object index is built on the first object-bound
    query (IndexedSPOAdjLists.ensureOpIndex). As in the Java loader, a sidecar that fails to
    parse or doesn't match this HDT is not used and the index is built instead.
    `self.sidecar_status` records what happened to the sidecar.
    """

    def __init__(self, data: bytes, opidx_bytes: bytes | None = None) -> None:
        r = _Reader(data)
        _read_control_info(r)
        _, hfmt, hprops = _read_control_info(r)
        if hfmt != "ntriples":
            raise HdtFormatError(f"unsupported header format {hfmt!r}")
        r.take(int(hprops["length"]))
        _, dfmt, _ = _read_control_info(r)
        if not dfmt.startswith("<http://purl.org/HDT/hdt#dictionaryFour"):
            raise HdtFormatError(f"unsupported dictionary format {dfmt!r}")
        psfc = dfmt == "<http://purl.org/HDT/hdt#dictionaryFourPsfc>"
        self.shared = PfcSection(r, False)
        self.subjects = PfcSection(r, False)
        self.predicates = PfcSection(r, False)
        self.objects = PfcSection(r, psfc)
        _, tfmt, tprops = _read_control_info(r)
        if tfmt != "<http://purl.org/HDT/hdt#triplesBitmap>":
            raise HdtFormatError(f"unsupported triples format {tfmt!r}")
        if tprops.get("order") != "1":
            raise HdtFormatError(f"unsupported triples order {tprops.get('order')!r} (SPO only)")
        self.bitmap_y = Bitmap.read(r)
        self.bitmap_z = Bitmap.read(r)
        self.y = Sequence(r)
        self.z = Sequence(r)
        self.sidecar_status = {"opidx": "absent"}
        sections = (self.shared, self.subjects, self.predicates, self.objects)
        self.index = K.TripleIndex(
            tuple(section.pfc for section in sections),
            tuple(section.num_strings for section in sections),
            self.objects.suffix_coded,
            (self.bitmap_y.data, self.bitmap_y.cum),
            (self.bitmap_z.data, self.bitmap_z.cum),
            (self.y.data, self.y.bits, self.y.entries),
            (self.z.data, self.z.bits, self.z.entries),
        )
        self._op_index = None
        self._load_op_index(opidx_bytes)

    def _load_op_index(self, opidx_bytes: bytes | None) -> None:
        """Install the sidecar's object index when it parses and covers every triple; otherwise
        ensure_op_index builds it on first use."""
        if opidx_bytes is None:
            return
        try:
            entries, max_object, seq, bitmap = read_opidx_sidecar(opidx_bytes)
        except HdtFormatError as e:
            self.sidecar_status["opidx"] = f"ignored: {e}"
            return
        if entries != self.z.entries:
            self.sidecar_status["opidx"] = (
                f"ignored: stale (entries={entries}, triples={self.z.entries})"
            )
            return
        self._install_op_index(seq.data, seq.bits, bitmap.data, bitmap.cum, max_object)
        self.sidecar_status["opidx"] = "used"

    def _install_op_index(self, positions, bits: int, boundaries, cum, max_object: int) -> None:
        self._op_index = (positions, bits, boundaries, cum, max_object)
        self.index.install_op_index(positions, bits, boundaries, cum, max_object)

    def ensure_op_index(self) -> None:
        """Build the object index unless a sidecar supplied it."""
        if self._op_index is not None:
            return
        n = self.z.entries
        max_o = K.scan_max_object(self.index)
        start = np.zeros(max_o + 2, dtype=np.int64)
        pos_bits = max(1, self.y.entries.bit_length())  # Wide enough for any Y position.
        positions = bytearray((n * pos_bits + 7) // 8)
        K.assemble_op_index(self.index, memoryview(start), memoryview(positions), pos_bits)
        boundaries = np.zeros((n + 7) // 8, dtype=np.uint8)
        starts = start[1 : max_o + 1]
        starts = starts[starts < n]
        np.bitwise_or.at(boundaries, starts >> 3, np.left_shift(1, starts & 7).astype(np.uint8))
        bitmap = memoryview(boundaries.tobytes())
        self._install_op_index(
            memoryview(positions), pos_bits, bitmap, _superblock_counts(bitmap), max_o
        )

    def op_index_arrays(self) -> tuple[np.ndarray, np.ndarray, int]:
        """The object index as (positions, run-start flags, max_object) arrays: temporaries, for
        writing a .opidx sidecar."""
        self.ensure_op_index()
        positions, bits, boundaries, _, max_object = self._op_index
        n = self.z.entries
        first = np.unpackbits(np.frombuffer(boundaries, dtype=np.uint8), bitorder="little")[:n]
        return _unpack(positions, bits, n), first.astype(bool), max_object

    # -- queries ------------------------------------------------------------
    def _object_needles(self, o: str) -> tuple[bytes, bytes]:
        """o as stored in the shared section and as stored in the objects section."""
        o_bytes = o.encode("utf-8")
        return o_bytes, K.psfc_encode_if_literal(o).encode(
            "utf-8"
        ) if self.objects.suffix_coded else o_bytes

    def has_triple(self, s: str, p: str, o: str) -> bool:
        o_bytes, o_own = self._object_needles(o)
        return self.index.contains(s.encode("utf-8"), p.encode("utf-8"), o_bytes, o_own)

    def string_triples(self, s: str | None = None, p: str | None = None, o: str | None = None):
        """PyStringTriple results for a triple pattern."""
        ix = self.index
        if s is not None and p is not None and o is not None:
            return iter((K.PyStringTriple(s, p, o),) if self.has_triple(s, p, o) else ())
        if s is not None and p is not None:
            return K.subject_predicate_triples(ix, s, s.encode("utf-8"), p, p.encode("utf-8"))
        if s is not None and o is not None:
            return K.subject_object_triples(ix, s, s.encode("utf-8"), o, *self._object_needles(o))
        if s is not None:
            return K.subject_triples(ix, s, s.encode("utf-8"))
        if p is not None and o is not None:
            self.ensure_op_index()
            return K.predicate_object_triples(ix, p, p.encode("utf-8"), o, *self._object_needles(o))
        if p is not None:
            return K.predicate_triples(ix, p, p.encode("utf-8"))
        if o is not None:
            self.ensure_op_index()
            return K.object_triples(ix, o, *self._object_needles(o))
        return K.all_triples(ix)

    def triples_with_pattern(
        self, s: str | None = None, p: str | None = None, o: str | None = None
    ):
        """(subject, predicate, object) tuples for a triple pattern."""
        return ((t.subject, t.predicate, t.object) for t in self.string_triples(s, p, o))

    def triples(self):
        """Full scan in SPO order, as tuples."""
        return self.triples_with_pattern()

    def subjects_with_po(self, p: str, o: str):
        return (t.subject for t in self.string_triples(None, p, o))

    def subjects_with_affixes(self, prefix: str, suffix: str | None = None) -> list[str]:
        return [t for _, t in self.shared.affix(prefix, suffix)] + [
            t for _, t in self.subjects.affix(prefix, suffix)
        ]

    def predicates_with_affixes(self, prefix: str, suffix: str | None = None) -> list[str]:
        return [t for _, t in self.predicates.affix(prefix, suffix)]

    def objects_with_affixes(self, prefix: str, suffix: str | None = None) -> list[str]:
        return [t for _, t in self.shared.affix(prefix, suffix)] + [
            t for _, t in self.objects.affix(prefix, suffix)
        ]
