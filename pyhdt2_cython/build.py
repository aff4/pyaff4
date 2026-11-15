#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""HDT generation: `from_triples` and sidecar writers.

The output follows an amalgam of the HDT metadata spec, hdt-java, hdt-rs and hdt-cpp: control
information with sorted properties (including `Software` and `numTriples`), a header that reports
counts, payload sizes and a `dc:issued` time, a four-section dictionary of length-prefixed
front-coded sections (type 8, so terms may contain NUL), and BitmapTriples. The dictionary is
`dictionaryFourPsfc` by default: typed literals in the objects section are stored suffix-coded.

The dictionary is built by a streamed intersection reorganiser: terms are interned per
role in arrival order (layer 1), each role is sorted (layer 2), the sorted subjects and
objects are merge-joined into the shared section and reduced to their subject-only and
object-only remainders (layer 3), and the layer 1 to 3 remaps are applied to the triples, which
are then radix-sorted into SPO order.
"""

from __future__ import annotations

import importlib.metadata
from datetime import UTC, datetime
from typing import NamedTuple

import crc32c
import numpy as np

from pyhdt2_cython import _kernels as K
from pyhdt2_cython.hdt import _crc8_smbus, _crc16_arc

BLOCK_SIZE = 16  # Dictionary default block size
SECTION_PFC_UTF8 = 8  # Dictionary section type: length-prefixed front coding
DISTRIBUTION = "pyaff4"

HDT = "http://purl.org/HDT/hdt#"
VOID = "http://rdfs.org/ns/void#"
DC = "http://purl.org/dc/terms/"
RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
HDT_CONTAINER = f"<{HDT}HDTv1>"
DICTIONARY_FOUR = f"{HDT}dictionaryFour"
DICTIONARY_FOUR_PSFC = f"{HDT}dictionaryFourPsfc"
TRIPLES_BITMAP = f"{HDT}triplesBitmap"


def _utc_now() -> datetime:
    """The clock behind the header's dc:issued time (tests patch this)."""
    return datetime.now(UTC)


def _software() -> str:
    try:
        version = importlib.metadata.version(DISTRIBUTION)
    except importlib.metadata.PackageNotFoundError as e:
        raise RuntimeError(
            f"cannot write the Software property: {DISTRIBUTION} has no installed metadata. "
            "Install the package (in the workspace: uv sync) rather than importing it from source."
        ) from e
    return f"{DISTRIBUTION}/{version}"


# ---------------------------------------------------------------------------
# Low-level encoders. The `_…_section` forms also return the payload size: the packed data only,
# without the type byte, VBytes and CRCs.
# ---------------------------------------------------------------------------


def encode_vbyte(n: int) -> bytes:
    """`n` as a VByte: 7-bit groups, low first, high bit on the last byte."""
    if n < 0:
        raise ValueError(f"VByte values must be non-negative, got {n}")
    out = bytearray()
    while n > 0x7F:
        out.append(n & 0x7F)
        n >>= 7
    out.append(n | 0x80)
    return bytes(out)


def control_info(ctype: int, fmt: str, props: dict[str, str]) -> bytes:
    """A control information block, its properties in sorted key order, each ending in `;`."""
    for key, value in props.items():
        if any(c in text for text in (key, value) for c in ";="):
            raise ValueError(f"control info property {key}={value} must not contain ';' or '='")
    body = (
        b"$HDT"
        + bytes([ctype])
        + fmt.encode()
        + b"\0"
        + "".join(f"{k}={props[k]};" for k in sorted(props)).encode()
        + b"\0"
    )
    return body + _crc16_arc(body).to_bytes(2, "little")


def pack_bits(values: np.ndarray, bits: int) -> bytes:
    """`bits`-wide integers packed LSB first, in ceil(bits * len / 8) bytes (the Log64 layout)."""
    if bits == 0 or len(values) == 0:
        return b""
    v = np.ascontiguousarray(values, dtype=np.uint64)
    out = bytearray((len(v) * bits + 7) // 8)
    K.pack_sequence(memoryview(v), bits, memoryview(out))
    return bytes(out)


def _sequence_section(values: np.ndarray, bits: int) -> tuple[bytes, int]:
    header = bytes([1, bits]) + encode_vbyte(len(values))
    body = pack_bits(values, bits)
    crc = crc32c.crc32c(body).to_bytes(4, "little")
    return header + bytes([_crc8_smbus(header)]) + body + crc, len(body)


def encode_sequence(values: np.ndarray) -> bytes:
    """HDT Log64 sequence section, with as many bits per entry as the largest value needs (at
    least 1)."""
    bits = max(1, int(values.max()).bit_length()) if len(values) else 1
    return _sequence_section(values, bits)[0]


def _bitmap_section(bits: np.ndarray) -> tuple[bytes, int]:
    header = bytes([1]) + encode_vbyte(len(bits))
    body = np.packbits(bits.astype(np.uint8), bitorder="little").tobytes()
    crc = crc32c.crc32c(body).to_bytes(4, "little")
    return header + bytes([_crc8_smbus(header)]) + body + crc, len(body)


def encode_bitmap(bits: np.ndarray) -> bytes:
    """HDT plain bitmap section: one bit per entry, in ceil(len / 8) bytes."""
    return _bitmap_section(bits)[0]


def _pfc_section(terms: _PackedTerms, ids: np.ndarray) -> tuple[bytes, int]:
    """Section type 8 (PlainFrontCodingUtf8): length-prefixed front coding of the packed terms
    `ids`, in that order, so terms may contain NUL. The payload is the packed strings plus the
    block offsets' packed data."""
    n = len(ids)
    ids = np.ascontiguousarray(ids, dtype=np.int64)
    term_bytes = int((terms.offsets[ids + 1] - terms.offsets[ids]).sum())
    # Up to two 5-byte VBytes per term: the shared count and the length of the rest.
    out = np.empty(term_bytes + n * 10 + 1, dtype=np.uint8)
    offsets = np.empty(n // BLOCK_SIZE + 2, dtype=np.uint64)
    used = K.pfc_encode(
        terms.data,
        memoryview(terms.offsets),
        memoryview(ids),
        BLOCK_SIZE,
        memoryview(out),
        memoryview(offsets),
    )
    packed = out[:used].tobytes()
    block_offsets = offsets[: (n + BLOCK_SIZE - 1) // BLOCK_SIZE + 1]
    offsets_section, offsets_payload = _sequence_section(
        block_offsets, max(1, int(block_offsets.max()).bit_length())
    )
    header = (
        bytes([SECTION_PFC_UTF8])
        + encode_vbyte(n)
        + encode_vbyte(len(packed))
        + encode_vbyte(BLOCK_SIZE)
    )
    section = (
        header
        + bytes([_crc8_smbus(header)])
        + offsets_section
        + packed
        + crc32c.crc32c(packed).to_bytes(4, "little")
    )
    return section, len(packed) + offsets_payload


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------


def _header_body(base_iri: str, facts: dict[str, int | str | None]) -> bytes:
    """The header's N-Triples, in the order of the agreed metadata spec."""
    base = f"<{base_iri}>"
    rdf_type = f"<{RDF_TYPE}>"
    dc_format = f"<{DC}format>"

    def lit(value: object) -> str:
        return f'"{value}"'

    rows = [
        (base, rdf_type, f"<{HDT}Dataset>"),
        (base, rdf_type, f"<{VOID}Dataset>"),
        (base, f"<{VOID}triples>", lit(facts["triples"])),
        (base, f"<{VOID}properties>", lit(facts["predicates"])),
        (base, f"<{VOID}distinctSubjects>", lit(facts["distinct_subjects"])),
        (base, f"<{VOID}distinctObjects>", lit(facts["distinct_objects"])),
        (base, f"<{HDT}formatInformation>", "_:format"),
        ("_:format", f"<{HDT}dictionary>", "_:dictionary"),
        ("_:format", f"<{HDT}triples>", "_:triples"),
        (base, f"<{HDT}statisticalInformation>", "_:statistics"),
        (base, f"<{HDT}publicationInformation>", "_:publicationInformation"),
        ("_:dictionary", dc_format, f"<{facts['dictionary_format']}>"),
        ("_:dictionary", f"<{HDT}dictionarynumSharedSubjectObject>", lit(facts["shared"])),
        ("_:dictionary", f"<{HDT}dictionarymapping>", lit(1)),
        ("_:dictionary", f"<{HDT}dictionarysizeStrings>", lit(facts["size_strings"])),
        ("_:dictionary", f"<{HDT}dictionaryblockSize>", lit(BLOCK_SIZE)),
        ("_:triples", dc_format, f"<{TRIPLES_BITMAP}>"),
        ("_:triples", f"<{HDT}triplesnumTriples>", lit(facts["triples"])),
        ("_:triples", f"<{HDT}triplesOrder>", lit("SPO")),
    ]
    if facts["original_size"] is not None:
        rows.append(("_:statistics", f"<{HDT}originalSize>", lit(facts["original_size"])))
    rows.append(("_:statistics", f"<{HDT}hdtSize>", lit(facts["hdt_size"])))
    rows.append(("_:publicationInformation", f"<{DC}issued>", lit(facts["issued"])))
    return "".join(f"{s} {p} {o} .\n" for s, p, o in rows).encode()


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------


class _PackedTerms(NamedTuple):
    """Terms sorted by their UTF-8 bytes (a layer 2 dictionary): term i is
    data[offsets[i]:offsets[i + 1]], and was term order[i] of the input list."""

    data: bytes
    offsets: np.ndarray
    order: np.ndarray


class _Layer1(NamedTuple):
    """Each role's distinct terms in arrival order, and each triple as indices into them."""

    subjects: list[str]
    predicates: list[str]
    objects: list[str]
    triples: np.ndarray


def _intern(triples_iter) -> _Layer1:
    """Layer 1: intern each role's terms, IRIs without their <>, in arrival order."""
    s_ids: dict[str, int] = {}
    p_ids: dict[str, int] = {}
    o_ids: dict[str, int] = {}
    s_id, p_id, o_id = s_ids.setdefault, p_ids.setdefault, o_ids.setdefault
    rows: list[int] = []
    add = rows.append
    # The <> stripping is inline: a helper call per term is a quarter of this loop's time.
    for s, p, o in triples_iter:
        if s[:1] == "<" and s[-1:] == ">":
            s = s[1:-1]
        if p[:1] == "<" and p[-1:] == ">":
            p = p[1:-1]
        if o[:1] == "<" and o[-1:] == ">":
            o = o[1:-1]
        add(s_id(s, len(s_ids)))
        add(p_id(p, len(p_ids)))
        add(o_id(o, len(o_ids)))
    triples = np.array(rows, dtype=np.int64).reshape(-1, 3)
    return _Layer1(list(s_ids), list(p_ids), list(o_ids), triples)


def _pack_sorted(terms: list[bytes]) -> _PackedTerms:
    """Terms already in byte order, packed: term i was term i of the input list."""
    offsets = np.zeros(len(terms) + 1, dtype=np.int64)
    np.cumsum(np.fromiter(map(len, terms), dtype=np.int64, count=len(terms)), out=offsets[1:])
    return _PackedTerms(b"".join(terms), offsets, np.arange(len(terms), dtype=np.int64))


def _sort_terms(terms: list[str]) -> _PackedTerms:
    """Layer 1 to 2: the terms sorted by their UTF-8 bytes."""
    encoded = [t.encode() for t in terms]
    order = sorted(range(len(encoded)), key=encoded.__getitem__)
    packed = _pack_sorted([encoded[i] for i in order])
    return packed._replace(order=np.array(order, dtype=np.int64))


def _intersect(subjects: _PackedTerms, objects: _PackedTerms) -> tuple[np.ndarray, np.ndarray]:
    """Each sorted subject's and object's shared id (from 1), or 0 for a term in only one role."""
    s_shared = np.zeros(len(subjects.order), dtype=np.int64)
    o_shared = np.zeros(len(objects.order), dtype=np.int64)
    K.intersect_sorted(
        subjects.data,
        memoryview(subjects.offsets),
        objects.data,
        memoryview(objects.offsets),
        memoryview(s_shared),
        memoryview(o_shared),
    )
    return s_shared, o_shared


def _layer1_to_3(sorted_terms: _PackedTerms, shared: np.ndarray, rest: np.ndarray) -> np.ndarray:
    """A role's layer 1 to 3 remap: shared terms take their shared id, and the role-only terms
    `rest` (layer 2 indices, in section order) follow the shared ids."""
    remap = np.empty(len(sorted_terms.order), dtype=np.uint64)
    in_shared = shared > 0
    remap[sorted_terms.order[in_shared]] = shared[in_shared]
    n_shared = int(np.count_nonzero(in_shared))
    remap[sorted_terms.order[rest]] = np.arange(n_shared + 1, n_shared + 1 + len(rest))
    return remap


def _objects_section(
    layer1: _Layer1, objects: _PackedTerms, only_o: np.ndarray, psfc: bool
) -> tuple[_PackedTerms, np.ndarray, np.ndarray]:
    """The objects-only section: its packed terms, the ids to encode in order, and each one's
    layer 2 object index. With `psfc`, typed literals are stored suffix-coded, which reorders
    the section."""
    if not psfc:
        return objects, only_o, only_o
    stored = [K.psfc_encode_if_literal(layer1.objects[i]) for i in objects.order[only_o]]
    suffix_coded = _sort_terms(stored)
    section_ids = np.arange(len(stored), dtype=np.int64)
    return suffix_coded, section_ids, only_o[suffix_coded.order]


def _sorted_ids(layer1: _Layer1, remaps: tuple[np.ndarray, ...], max_ids: tuple[int, ...]):
    """The triples' (s, p, o) layer 3 ids, sorted into SPO order without repeats."""
    s, p, o = (remap[layer1.triples[:, k]] for k, remap in enumerate(remaps))
    scratch = tuple(memoryview(np.empty(len(s), dtype=np.uint64)) for _ in range(3))
    bits = tuple(m.bit_length() for m in max_ids)
    kept = K.sort_unique_triples(memoryview(s), memoryview(p), memoryview(o), scratch, bits)
    return s[:kept], p[:kept], o[:kept]


def _bitmap_triples(s: np.ndarray, p: np.ndarray, o: np.ndarray, y_bits: int, z_bits: int):
    """Bitmaps Y and Z and sequences Y and Z (`y_bits` / `z_bits` wide) for sorted, distinct
    (s, p, o) ids and their total payload size.

    Bitmaps have one bit per entry, set on the last predicate of each subject (Y) and the last
    object of each (subject, predicate) pair (Z); an empty graph has empty bitmaps.
    """
    n = len(s)
    if n == 0:
        empty = np.zeros(0, dtype=np.uint64)
        y_marks = z_marks = np.zeros(0, dtype=bool)
        predicates = objects = empty
    else:
        new_sp = np.ones(n, dtype=bool)
        new_sp[1:] = (s[1:] != s[:-1]) | (p[1:] != p[:-1])
        y_idx = np.flatnonzero(new_sp)
        y_subject = s[y_idx]
        y_marks = np.ones(len(y_idx), dtype=bool)
        y_marks[:-1] = y_subject[1:] != y_subject[:-1]
        z_marks = np.ones(n, dtype=bool)
        z_marks[:-1] = new_sp[1:]
        predicates, objects = p[y_idx], o
    parts = [
        _bitmap_section(y_marks),
        _bitmap_section(z_marks),
        _sequence_section(predicates, y_bits),
        _sequence_section(objects, z_bits),
    ]
    return b"".join(section for section, _ in parts), sum(size for _, size in parts)


# A streamed intersection reorganiser generates the HDT: sort subjects and objects,
# merge-intersect them into the shared section, reduce what's left to subject-only and object-only
# sections, chain the layer 1 → 3 remaps, then remap and radix-sort the triples.
#   1. Layer 1, intern (Python): each role's terms (subjects, predicates, objects) are interned in
#      arrival order, with <> stripped from IRIs. Each triple becomes three layer-1 ids.
#   2. Layer 1 → 2, sort: each role's terms are sorted by their UTF-8 bytes and
#      packed into one buffer with offsets. The new→old order is kept.
#   3. Intersect (Cython): one merge-join pass over the sorted subjects and objects. Terms found in
#      both get shared ids 1, 2, 3… in sorted order, and those ids are the shared section.
#   4. Layer 2 → 3, reduce: the sorted subjects and objects that aren't shared are the subject-only
#      and object-only sections, already in order. With psfc, the object-only section is re-sorted
#      by its suffix-coded form.
#   5. Remap chains:
#      - Each subject and object maps from layer 1 straight to layer 3: shared terms take their
#        shared id, and the rest take n_shared + position.
#      - Predicates map to their sorted position.
#   6. Remap and sort the triples (Cython): the remaps are applied to the triples. An LSD radix sort
#      (stable passes of up to 16 bits over o, then p, then s) puts them in SPO order, and duplicate
#      rows are dropped in the same pass.
#   7. Encode (Cython): the four sections are front-coded straight from the packed buffers, and the
#      BitmapTriples bitmaps and sequences are built and packed.
def _build(triples_iter, base_iri: str, original_size: int | None, psfc: bool) -> bytes:
    if original_size is not None and original_size < 0:
        raise ValueError(f"original_size must be non-negative, got {original_size}")
    software = _software()
    layer1 = _intern(triples_iter)
    subjects = _sort_terms(layer1.subjects)
    objects = _sort_terms(layer1.objects)
    predicates = _sort_terms(layer1.predicates)
    s_shared, o_shared = _intersect(subjects, objects)
    shared_ids = np.flatnonzero(s_shared)
    only_s = np.flatnonzero(s_shared == 0)
    o_section, o_section_ids, only_o = _objects_section(
        layer1, objects, np.flatnonzero(o_shared == 0), psfc
    )
    n_shared = len(shared_ids)
    n_preds = len(predicates.order)
    max_object = n_shared + len(only_o)

    s_remap = _layer1_to_3(subjects, s_shared, only_s)
    o_remap = _layer1_to_3(objects, o_shared, only_o)
    p_remap = np.empty(n_preds, dtype=np.uint64)
    p_remap[predicates.order] = np.arange(1, n_preds + 1)
    s, p, o = _sorted_ids(
        layer1, (s_remap, p_remap, o_remap), (n_shared + len(only_s), n_preds, max_object)
    )
    n = len(s)

    sections = [
        _pfc_section(subjects, shared_ids),
        _pfc_section(subjects, only_s),
        _pfc_section(predicates, np.arange(n_preds)),
        _pfc_section(o_section, o_section_ids),
    ]
    size_strings = sum(size for _, size in sections)
    triples_body, triples_size = _bitmap_triples(
        s, p, o, n_preds.bit_length(), max_object.bit_length()
    )
    dictionary_format = DICTIONARY_FOUR_PSFC if psfc else DICTIONARY_FOUR
    header = _header_body(
        base_iri,
        {
            "triples": n,
            "predicates": n_preds,
            "distinct_subjects": n_shared + len(only_s),
            "distinct_objects": max_object,
            "dictionary_format": dictionary_format,
            "shared": n_shared,
            "size_strings": size_strings,
            "original_size": original_size,
            "hdt_size": size_strings + triples_size,
            "issued": _utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    )
    n_terms = n_shared + len(only_s) + n_preds + len(only_o)
    return b"".join(
        [
            control_info(1, HDT_CONTAINER, {"Software": software}),
            control_info(2, "ntriples", {"length": str(len(header))}),
            header,
            control_info(3, f"<{dictionary_format}>", {"elements": str(n_terms)}),
            *(section for section, _ in sections),
            control_info(4, f"<{TRIPLES_BITMAP}>", {"numTriples": str(n), "order": "1"}),
            triples_body,
        ]
    )


def from_triples(
    triples,
    base_iri: str = "urn:hdt:in-memory",
    *,
    original_size: int | None = None,
    psfc: bool = True,
) -> bytes:
    """HDT file bytes for (s, p, o) term strings in dictionary storage form.

    IRIs may be given with or without <>. `original_size` (the source's size in bytes) is written
    as hdt:originalSize when given. `psfc=False` writes a plain `dictionaryFour` dictionary.
    """
    return _build(triples, base_iri, original_size, psfc)


# ---------------------------------------------------------------------------
# OP Index writer
# ---------------------------------------------------------------------------


def write_opidx_sidecar(op_seq: np.ndarray, first: np.ndarray, max_object: int) -> bytes:
    """A .opidx sidecar holding the object index, as read_opidx_sidecar reads it.

    Header
      u8     type        = 0x03
      VByte  entries     sequence length == bitmap numBits == triple count (staleness key)
      VByte  maxObject   largest object id == bitmap set-bit count
      u8     headerCRC8  CRC-8 over the header bytes above
    Sequence section     the positions sequence (HDT Log64; see Sequence in hdt.py)
    Bitmap section       the object-boundary bitmap (HDT plain bitmap; see Bitmap in hdt.py)
    """
    header = bytes([0x03]) + encode_vbyte(len(op_seq)) + encode_vbyte(max_object)
    return header + bytes([_crc8_smbus(header)]) + encode_sequence(op_seq) + encode_bitmap(first)
