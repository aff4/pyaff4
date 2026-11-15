#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Hot loops for the HDT engine, in Cython pure-Python mode.

The same file runs interpreted (plain Python) or compiled by Cython. Bit tricks branch on
`cython.compiled` because C and Python integers differ (fixed-width wraparound vs. unbounded).
All functions take memoryviews or integers; numpy arrays are wrapped in `memoryview` by callers
so that interpreted indexing yields Python ints.
"""

import cython

u64 = cython.typedef(cython.ulonglong)
i64 = cython.typedef(cython.longlong)
idx = cython.typedef(cython.Py_ssize_t)

# Python-visible names for callers; the C-typed copies below are what the hot loops read.
ENC_NUL_TERMINATED = 0
ENC_LENGTH_PREFIXED = 1
ENC_LENGTH_PREFIXED_NUL = 2
_ENC_NUL = cython.declare(cython.int, 0)
_ENC_LEN = cython.declare(cython.int, 1)
_ENC_LEN_NUL = cython.declare(cython.int, 2)


# ---------------------------------------------------------------------------
# Bit primitives
# ---------------------------------------------------------------------------


@cython.cfunc
@cython.inline
@cython.exceptval(check=False)
def _ones() -> u64:
    if cython.compiled:
        return cython.cast(u64, -1)
    else:
        return 0xFFFFFFFFFFFFFFFF


@cython.cfunc
@cython.inline
@cython.exceptval(check=False)
def _popcount(x: u64) -> cython.int:
    if cython.compiled:
        ones: u64 = cython.cast(u64, -1)
        m1: u64 = ones // 3
        m2: u64 = ones // 5
        m4: u64 = ones // 17
        h01: u64 = ones // 255
        x = x - ((x >> 1) & m1)
        x = (x & m2) + ((x >> 2) & m2)
        x = (x + (x >> 4)) & m4
        return cython.cast(cython.int, (x * h01) >> 56)
    else:
        return x.bit_count()


@cython.cfunc
@cython.inline
@cython.exceptval(check=False)
def _low_mask(nbits: cython.int) -> u64:
    if nbits >= 64:
        return _ones()
    return (cython.cast(u64, 1) << nbits) - 1


@cython.cfunc
@cython.exceptval(check=False)
def _select_in_word(w: u64, k: cython.int) -> cython.int:
    """Bit index of the set bit with 0-based rank k in w, or 64 if w has no such bit."""
    pos: cython.int = 0
    c: cython.int = _popcount(w & 0xFF)
    while k >= c and pos < 64:
        k -= c
        w >>= 8
        pos += 8
        c = _popcount(w & 0xFF)
    while pos < 64:
        if w & 1:
            if k == 0:
                return pos
            k -= 1
        w >>= 1
        pos += 1
    return 64


# ---------------------------------------------------------------------------
# In-place reads. Bitmaps and packed integer sequences (HDT LogArray) are read straight from the
# HDT or sidecar bytes: words are assembled little-endian from bytes, so neither alignment nor a
# whole number of words is needed, and bytes past the end read as zero.
# ---------------------------------------------------------------------------


@cython.cfunc
@cython.inline
@cython.boundscheck(False)
@cython.wraparound(False)
@cython.exceptval(check=False)
def _word(data: cython.const[cython.uchar][::1], w: idx) -> u64:
    """Little-endian 64-bit word `w` of data; bytes past the end read as zero."""
    pos: idx = w << 3
    n: idx = len(data)
    v: u64 = 0
    k: cython.int
    if pos + 8 <= n:
        for k in range(8):
            v |= cython.cast(u64, data[pos + k]) << (k * 8)
        return v
    for k in range(8):
        if pos + k < n:
            v |= cython.cast(u64, data[pos + k]) << (k * 8)
    return v


@cython.cfunc
@cython.inline
@cython.exceptval(check=False)
def _bit(data: cython.const[cython.uchar][::1], i: idx) -> cython.int:
    return cython.cast(cython.int, (_word(data, i >> 6) >> (i & 63)) & 1)


@cython.ccall
@cython.boundscheck(False)
@cython.wraparound(False)
def bm_rank1(words: cython.const[cython.uchar][::1], cum: u64[::1], i: idx) -> idx:
    """Number of set bits in positions [0, i). `cum` holds one running count per 512 bits."""
    b: idx = i >> 9
    r: idx = cython.cast(idx, cum[b])
    w: idx = i >> 6
    j: idx
    for j in range(b * 8, w):
        r += _popcount(_word(words, j))
    off: cython.int = cython.cast(cython.int, i & 63)
    if off:
        r += _popcount(_word(words, w) & _low_mask(off))
    return r


@cython.ccall
@cython.boundscheck(False)
@cython.wraparound(False)
def bm_select1(words: cython.const[cython.uchar][::1], cum: u64[::1], k: idx) -> idx:
    """Position of the set bit with 0-based rank k, or -1 if there are not that many."""
    nb: idx = len(cum) - 1
    if k < 0 or cython.cast(u64, k) >= cum[nb]:
        return -1
    lo: idx = 0
    hi: idx = nb
    mid: idx
    while hi - lo > 1:
        mid = (lo + hi) >> 1
        if cum[mid] <= cython.cast(u64, k):
            lo = mid
        else:
            hi = mid
    k -= cython.cast(idx, cum[lo])
    j: idx = lo * 8
    n_words: idx = (len(words) + 7) >> 3
    c: cython.int
    w: u64
    while j < n_words:
        w = _word(words, j)
        c = _popcount(w)
        if k < c:
            return j * 64 + _select_in_word(w, cython.cast(cython.int, k))
        k -= c
        j += 1
    return -1


@cython.ccall
@cython.boundscheck(False)
@cython.wraparound(False)
def seq_get(data: cython.const[cython.uchar][::1], bits: cython.int, i: idx) -> idx:
    """Entry i of a packed sequence: `bits`-wide integers, LSB-first."""
    bitpos: idx = i * bits
    wi: idx = bitpos >> 6
    off: cython.int = cython.cast(cython.int, bitpos & 63)
    v: u64 = _word(data, wi) >> off
    if off + bits > 64:
        v |= _word(data, wi + 1) << (64 - off)
    return cython.cast(idx, v & _low_mask(bits))


@cython.cfunc
@cython.boundscheck(False)
@cython.wraparound(False)
@cython.exceptval(check=False)
def _seq_set(data: cython.uchar[::1], bits: cython.int, i: idx, value: idx) -> cython.int:
    """Store `value` as entry i of a packed sequence (the writing side of seq_get)."""
    bitpos: idx = i * bits
    pos: idx = bitpos >> 3
    shift: cython.int = cython.cast(cython.int, bitpos & 7)
    left: cython.int = bits
    v: u64 = cython.cast(u64, value)
    take: cython.int
    mask: cython.int
    while left > 0:
        take = 8 - shift if 8 - shift < left else left
        mask = ((1 << take) - 1) << shift
        data[pos] = cython.cast(
            cython.uchar, (data[pos] & ~mask) | ((cython.cast(cython.int, v) << shift) & mask)
        )
        v >>= take
        left -= take
        pos += 1
        shift = 0
    return 0


# ---------------------------------------------------------------------------
# VByte: 7-bit groups, least significant first, high bit set on the last byte.
# Front-coded dictionary sections are below, in the Pfc class.
# ---------------------------------------------------------------------------


@cython.cfunc
@cython.inline
@cython.boundscheck(False)
@cython.wraparound(False)
@cython.exceptval(check=False)
def _write_vbyte(out: cython.uchar[::1], pos: idx, value: idx) -> idx:
    """Write non-negative `value` as a VByte at `pos`; return the next pos."""
    while value > 0x7F:
        out[pos] = cython.cast(cython.uchar, value & 0x7F)
        pos += 1
        value >>= 7
    out[pos] = cython.cast(cython.uchar, value | 0x80)
    return pos + 1


@cython.cfunc
def _corrupt(what: str, offset: idx) -> cython.int:
    """Raise ValueError for a malformed dictionary section (cold path, out of the hot loops)."""
    raise ValueError(f"malformed front-coded dictionary section: {what} at byte {offset}")


@cython.cfunc
def _out_of_range(local_id: idx, count: idx) -> cython.int:
    raise IndexError(f"string id {local_id} is out of range 1..{count}")


@cython.cfunc
def _bad_term(what: str, index: idx) -> cython.int:
    raise ValueError(f"cannot front-code term {index}: {what}")


@cython.cfunc
@cython.inline
@cython.boundscheck(False)
@cython.wraparound(False)
@cython.exceptval(-1, check=False)
def _vbyte_end(data: cython.const[cython.uchar][::1], pos: idx, limit: idx) -> idx:
    """Position just after the VByte at `pos`: at most 5 bytes."""
    i: idx = pos
    end: idx = pos + 5
    while i < limit and i < end:
        if data[i] & 0x80:
            return i + 1
        i += 1
    _corrupt("VByte longer than 5 bytes" if i == end else "VByte past the end of its block", pos)
    return -1


@cython.cfunc
@cython.inline
@cython.boundscheck(False)
@cython.wraparound(False)
@cython.exceptval(check=False)
def _vbyte_value(data: cython.const[cython.uchar][::1], pos: idx, end: idx) -> idx:
    """Value of the VByte in data[pos:end]: 7-bit groups, least significant first."""
    value: idx = 0
    shift: cython.int = 0
    while pos < end:
        value |= cython.cast(idx, data[pos] & 0x7F) << shift
        shift += 7
        pos += 1
    return value


@cython.cfunc
@cython.inline
@cython.exceptval(-1, check=False)
def _string_start(
    data: cython.const[cython.uchar][::1], pos: idx, limit: idx, enc: cython.int
) -> idx:
    """Where the string at `pos` starts: at `pos` for NUL-terminated sections (type 2), after its
    VByte length for length-prefixed ones (types 7 and 8)."""
    if enc == _ENC_NUL:
        return pos
    return _vbyte_end(data, pos, limit)


@cython.cfunc
@cython.inline
@cython.boundscheck(False)
@cython.wraparound(False)
@cython.exceptval(-1, check=False)
def _string_len(
    data: cython.const[cython.uchar][::1], pos: idx, start: idx, limit: idx, enc: cython.int
) -> idx:
    """Length of the string at `pos` whose bytes begin at `start` (see _string_start).

    Type 2 scans for the NUL (NullIntolerant's strlen); types 7 and 8 read the VByte length, and
    the string (plus the type-7 NUL) must fit before `limit`.
    """
    p: idx
    n: idx
    if enc == _ENC_NUL:
        p = start
        while p < limit and data[p] != 0:
            p += 1
        if p >= limit:
            _corrupt("string without a NUL terminator", pos)
            return -1
        return p - start
    n = _vbyte_value(data, pos, start)
    if start + n + (1 if enc == _ENC_LEN_NUL else 0) > limit:
        _corrupt("string longer than its block", pos)
        return -1
    return n


@cython.cfunc
@cython.inline
@cython.boundscheck(False)
@cython.wraparound(False)
@cython.exceptval(check=False)
def _copy(
    dst: cython.uchar[::1], at: idx, src: cython.const[cython.uchar][::1], start: idx, n: idx
) -> cython.int:
    """dst[at:at + n] = src[start:start + n] (fillFromBuckets); dst must already be big enough."""
    k: idx
    for k in range(n):
        dst[at + k] = src[start + k]
    return 0


@cython.cfunc
@cython.inline
@cython.boundscheck(False)
@cython.wraparound(False)
@cython.exceptval(check=False)
def _common_bytes(
    data: cython.const[cython.uchar][::1],
    start: idx,
    n: idx,
    needle: cython.const[cython.uchar][::1],
    k: idx,
) -> idx:
    """k plus the number of leading bytes data[start:start + n] shares with needle[k:]."""
    m: idx = len(needle)
    end: idx = start + n
    while start < end and k < m and data[start] == needle[k]:
        start += 1
        k += 1
    return k


@cython.cfunc
@cython.inline
@cython.boundscheck(False)
@cython.wraparound(False)
@cython.exceptval(check=False)
def _ends_with(
    data: cython.const[cython.uchar][::1], end: idx, suffix: cython.const[cython.uchar][::1]
) -> cython.bint:
    """Whether data[:end] ends with suffix; end must be at least len(suffix)."""
    n: idx = len(suffix)
    k: idx
    for k in range(n):
        if data[end - n + k] != suffix[k]:
            return False
    return True


# ---------------------------------------------------------------------------
# PFC section as a compiled object: buffers acquired once, strings decoded in C
# ---------------------------------------------------------------------------


@cython.final
@cython.auto_pickle(False)
@cython.cclass
class Pfc:
    """A front-coded dictionary section, read as section
    types 7 and 8: VByte-length-prefixed strings, with or without a trailing NUL and
    type 2: NUL-terminated strings.

    Each block stores its first string whole, then each further string as a VByte count of bytes
    retained from the previous string followed by the rest. Ids are 1-based. Entries are read
    where they lie; a string is rebuilt only when returned, in a reused scratch buffer, from a
    reused record of its block's entry layout (safe: compiled methods hold the GIL for their whole
    duration).
    """

    packed: cython.const[cython.uchar][::1]
    offs: cython.const[cython.uchar][::1]
    offs_bits: cython.int
    n_offs: idx
    block_size: idx
    enc: cython.int
    count: idx
    scratch: cython.uchar[::1]
    scratch_obj: bytearray
    layout: i64[::1]

    def __init__(
        self,
        packed,
        offs,
        offs_bits: cython.int,
        n_offs: idx,
        block_size: idx,
        enc: cython.int,
        count: idx,
    ):
        self.packed = packed
        self.offs = offs
        self.offs_bits = offs_bits
        self.n_offs = n_offs
        self.block_size = block_size
        self.enc = enc
        self.count = count
        self.scratch_obj = bytearray(4096)
        self.scratch = self.scratch_obj
        # Per entry of a block: its retained count and where its suffix starts.
        self.layout = memoryview(bytearray(2 * block_size * 8)).cast("q")

    @cython.cfunc
    def _grow(self, at_least: idx):
        size: idx = len(self.scratch_obj) * 2
        if size < at_least:
            size = at_least
        self.scratch_obj = bytearray(size)
        self.scratch = self.scratch_obj

    # -- reading ------------------------------------------------------------------------------

    @cython.cfunc
    def _text(self, n: idx) -> str:
        """The first n bytes of the scratch buffer, decoded as UTF-8."""
        if cython.compiled:
            p: cython.p_char = cython.cast(cython.p_char, cython.address(self.scratch[0]))
            return p[:n].decode("utf-8")
        else:
            return bytes(self.scratch_obj[:n]).decode("utf-8")

    @cython.cfunc
    @cython.boundscheck(False)
    @cython.initializedcheck(False)
    @cython.wraparound(False)
    def _fill(self, last: idx, n: idx) -> cython.int:
        """Rebuild entry `last` of the block in self.layout, n bytes long, in the scratch buffer.

        Use the technique of fastutil's front coding: fill the string from the end, taking from
        each entry, last first, just the suffix bytes no later entry replaces.
        """
        if n > len(self.scratch):
            self._grow(n)
        hi: idx = n
        i: idx = last
        retained: idx
        while hi > 0:
            retained = cython.cast(idx, self.layout[2 * i])
            if hi > retained:
                _copy(
                    self.scratch,
                    retained,
                    self.packed,
                    cython.cast(idx, self.layout[2 * i + 1]),
                    hi - retained,
                )
                hi = retained
            i -= 1
        return 0

    @cython.cfunc
    @cython.boundscheck(False)
    @cython.initializedcheck(False)
    @cython.wraparound(False)
    def _fill_if_ends_with(
        self, last: idx, start: idx, length: idx, n: idx, suffix: cython.const[cython.uchar][::1]
    ) -> cython.bint:
        """Whether entry `last` (n bytes, its suffix `length` bytes at `start`) ends with suffix;
        if so, rebuild it in the scratch buffer. A suffix within the stored bytes is compared in
        place, so a mismatch rebuilds nothing."""
        if len(suffix) > n:
            return False
        if len(suffix) <= length:
            if not _ends_with(self.packed, start + length, suffix):
                return False
            self._fill(last, n)
            return True
        self._fill(last, n)
        return _ends_with(self.scratch, n, suffix)

    @cython.ccall
    @cython.boundscheck(False)
    @cython.initializedcheck(False)
    @cython.wraparound(False)
    def extract(self, local_id: idx) -> str:
        """String `local_id` (1-based).

        Copies only the bytes that end up in the string: a forward pass records each entry's
        layout up to the target, then _fill rebuilds the target from the end.
        """
        if local_id < 1 or local_id > self.count:
            _out_of_range(local_id, self.count)
            return ""
        block: idx = (local_id - 1) // self.block_size
        target: idx = (local_id - 1) % self.block_size
        block_end: idx = seq_get(self.offs, self.offs_bits, block + 1)
        pos: idx = seq_get(self.offs, self.offs_bits, block)
        n: idx = 0
        retained: idx = 0
        start: idx
        length: idx
        vbyte_end: idx
        i: idx
        for i in range(target + 1):
            if i > 0:
                if pos >= block_end:
                    _corrupt("block ends before the requested entry", pos)
                    return ""
                vbyte_end = _vbyte_end(self.packed, pos, block_end)
                retained = _vbyte_value(self.packed, pos, vbyte_end)
                if retained > n:
                    # A well-formed entry shares at most the whole previous string. Refusing here
                    # also stops a corrupt count (up to 2^35) from sizing the scratch buffer.
                    _corrupt("entry retains more bytes than the previous string has", pos)
                    return ""
                pos = vbyte_end
            start = _string_start(self.packed, pos, block_end, self.enc)
            length = _string_len(self.packed, pos, start, block_end, self.enc)
            self.layout[2 * i] = retained
            self.layout[2 * i + 1] = start
            n = retained + length
            pos = start + length + (0 if self.enc == _ENC_LEN else 1)
        self._fill(target, n)
        return self._text(n)

    @cython.cfunc
    @cython.boundscheck(False)
    @cython.initializedcheck(False)
    @cython.wraparound(False)
    @cython.exceptval(-2, check=False)
    def _compare_head(self, block: idx, needle: cython.const[cython.uchar][::1]) -> cython.int:
        """Sign of (first string of `block`) - needle, compared as unsigned bytes."""
        pos: idx = seq_get(self.offs, self.offs_bits, block)
        # The section end bounds the read: one offset lookup fewer per binary-search probe.
        limit: idx = len(self.packed)
        start: idx = _string_start(self.packed, pos, limit, self.enc)
        n: idx = _string_len(self.packed, pos, start, limit, self.enc)
        m: idx = len(needle)
        k: idx
        for k in range(n if n < m else m):
            if self.packed[start + k] != needle[k]:
                return -1 if self.packed[start + k] < needle[k] else 1
        if n == m:
            return 0
        return -1 if n < m else 1

    @cython.cfunc
    @cython.exceptval(-2, check=False)
    def _head_block(self, needle: cython.const[cython.uchar][::1]) -> idx:
        """The last block whose first string sorts at or before needle, or -1 if needle sorts
        before every block."""
        lo: idx = 0
        hi: idx = self.n_offs - 2
        mid: idx
        while lo <= hi:
            mid = (lo + hi) >> 1
            if self._compare_head(mid, needle) <= 0:
                lo = mid + 1
            else:
                hi = mid - 1
        return hi

    @cython.ccall
    def locate(self, needle: bytes) -> idx:
        """1-based id of `needle` (UTF-8), or 0 if absent.

        Binary search the blocks' first strings, then search
        the last block whose first string sorts at or before needle.
        """
        q: cython.const[cython.uchar][::1] = needle
        block: idx
        found: idx
        if self.count == 0 or self.n_offs < 2:
            return 0
        block = self._head_block(q)
        if block < 0:
            return 0
        found = self._locate_in_block(block, q)
        return 0 if found < 0 else block * self.block_size + found + 1

    @cython.cfunc
    @cython.boundscheck(False)
    @cython.initializedcheck(False)
    @cython.wraparound(False)
    @cython.exceptval(-2, check=False)
    def _locate_in_block(self, block: idx, needle: cython.const[cython.uchar][::1]) -> idx:
        """0-based position of needle in `block` (0 is its first string), or -1.

        Compares each entry with needle where it lies, without rebuilding it. `common` is how many
        leading bytes the previous entry shares with needle. An entry retaining more than that
        matches the previous entry at the first differing byte, so it still sorts before needle
        and is skipped unread; otherwise only its stored suffix is compared, from byte `retained`
        on. This holds whether writers count retained bytes in whole characters
        or bytewise. The scan stops at the first entry that sorts after
        needle, so a miss reads no further than where needle would be.
        """
        block_end: idx = seq_get(self.offs, self.offs_bits, block + 1)
        pos: idx = seq_get(self.offs, self.offs_bits, block)
        m: idx = len(needle)
        common: idx = 0
        prev_len: idx = 0
        retained: idx = 0
        start: idx
        length: idx
        vbyte_end: idx
        entry: idx
        for entry in range(self.block_size):
            if entry > 0:
                if pos >= block_end:
                    return -1
                vbyte_end = _vbyte_end(self.packed, pos, block_end)
                retained = _vbyte_value(self.packed, pos, vbyte_end)
                if retained > prev_len:
                    _corrupt("entry retains more bytes than the previous string has", pos)
                    return -2
                pos = vbyte_end
            start = _string_start(self.packed, pos, block_end, self.enc)
            length = _string_len(self.packed, pos, start, block_end, self.enc)
            pos = start + length + (0 if self.enc == _ENC_LEN else 1)
            prev_len = retained + length
            if retained <= common:
                common = _common_bytes(self.packed, start, length, needle, retained)
                if common == m:
                    return entry if prev_len == m else -1
                if common < prev_len and self.packed[start + common - retained] > needle[common]:
                    return -1
        return -1

    @cython.ccall
    @cython.boundscheck(False)
    @cython.initializedcheck(False)
    @cython.wraparound(False)
    def affix(self, prefix: bytes, suffix: bytes) -> list:
        """(id, string) for each entry that starts with prefix and, if suffix is non-empty, ends
        with it. Comparison is bytewise on the stored form. An empty prefix yields nothing.

        The entries are sorted, so the matches are one run: start at the last block whose first
        string sorts at or before prefix, compare each entry with prefix in place as
        _locate_in_block compares with its needle, and stop at the first entry that sorts after
        prefix without starting with it. Only matches are rebuilt, as extract rebuilds them.
        """
        out: list = []
        pre: cython.const[cython.uchar][::1] = prefix
        suf: cython.const[cython.uchar][::1] = suffix
        npre: idx = len(prefix)
        if npre == 0 or self.count == 0 or self.n_offs < 2:
            return out
        block: idx = self._head_block(pre)
        if block < 0:
            block = 0
        local_id: idx = block * self.block_size + 1
        entry: idx = 0
        block_end: idx = 0
        pos: idx = 0
        n: idx = 0
        retained: idx = 0
        common: idx = 0
        start: idx
        length: idx
        vbyte_end: idx
        while local_id <= self.count:
            if entry == 0:
                block_end = seq_get(self.offs, self.offs_bits, block + 1)
                pos = seq_get(self.offs, self.offs_bits, block)
                retained = 0
            else:
                vbyte_end = _vbyte_end(self.packed, pos, block_end)
                retained = _vbyte_value(self.packed, pos, vbyte_end)
                if retained > n:
                    _corrupt("entry retains more bytes than the previous string has", pos)
                    return out
                pos = vbyte_end
            start = _string_start(self.packed, pos, block_end, self.enc)
            length = _string_len(self.packed, pos, start, block_end, self.enc)
            self.layout[2 * entry] = retained
            self.layout[2 * entry + 1] = start
            n = retained + length
            pos = start + length + (0 if self.enc == _ENC_LEN else 1)
            if retained <= common:
                common = _common_bytes(self.packed, start, length, pre, retained)
                if (
                    common < npre
                    and common < n
                    and self.packed[start + common - retained] > pre[common]
                ):
                    break
            if common == npre and self._fill_if_ends_with(entry, start, length, n, suf):
                out.append((local_id, self._text(n)))
            local_id += 1
            entry += 1
            if entry == self.block_size:
                entry = 0
                block += 1
        return out


# ---------------------------------------------------------------------------
# Generation. Terms are handled as one packed UTF-8 buffer: term i is
# data[offsets[i]:offsets[i + 1]], and a section is a list of term indices into it.
# ---------------------------------------------------------------------------


@cython.cfunc
@cython.inline
@cython.boundscheck(False)
@cython.wraparound(False)
@cython.exceptval(check=False)
def _compare_terms(
    a: cython.const[cython.uchar][::1],
    a0: idx,
    a1: idx,
    b: cython.const[cython.uchar][::1],
    b0: idx,
    b1: idx,
) -> cython.int:
    """-1, 0 or 1 as a[a0:a1] sorts before, equal to or after b[b0:b1] in byte order (which for
    UTF-8 is code point order)."""
    while a0 < a1 and b0 < b1:
        if a[a0] != b[b0]:
            return -1 if a[a0] < b[b0] else 1
        a0 += 1
        b0 += 1
    if a0 < a1:
        return 1
    return -1 if b0 < b1 else 0


@cython.ccall
@cython.boundscheck(False)
@cython.wraparound(False)
def intersect_sorted(
    a: cython.const[cython.uchar][::1],
    a_offsets: cython.const[i64][::1],
    b: cython.const[cython.uchar][::1],
    b_offsets: cython.const[i64][::1],
    a_shared: i64[::1],
    b_shared: i64[::1],
) -> idx:
    """Merge-join two strictly increasing packed term lists (DictOperators.intersection).

    Each term found in both gets the next shared id, counting from 1, in a_shared and b_shared at
    its index on each side; the other entries are left as they are (callers pass zeroes). Returns
    the number of shared terms.
    """
    na: idx = len(a_offsets) - 1
    nb: idx = len(b_offsets) - 1
    i: idx = 0
    j: idx = 0
    shared: idx = 0
    c: cython.int
    while i < na and j < nb:
        c = _compare_terms(
            a,
            cython.cast(idx, a_offsets[i]),
            cython.cast(idx, a_offsets[i + 1]),
            b,
            cython.cast(idx, b_offsets[j]),
            cython.cast(idx, b_offsets[j + 1]),
        )
        if c < 0:
            i += 1
        elif c > 0:
            j += 1
        else:
            shared += 1
            a_shared[i] = shared
            b_shared[j] = shared
            i += 1
            j += 1
    return shared


@cython.ccall
@cython.boundscheck(False)
@cython.wraparound(False)
def pfc_encode(
    data: cython.const[cython.uchar][::1],
    offsets: cython.const[i64][::1],
    ids: cython.const[i64][::1],
    block_size: idx,
    out: cython.uchar[::1],
    block_offsets: cython.ulonglong[::1],
) -> idx:
    """Front-code the packed terms `ids` (in that order, which must be strictly increasing byte
    order) into `out` in the length-prefixed layout (section type 8, PlainFrontCodingUtf8).

    The first term of each block is stored as a VByte length followed by its bytes, and every
    other term as a VByte count of bytes shared with the previous term, a VByte length of the
    rest, then the rest. Terms may contain NUL. The shared count covers whole characters only.
    `out` needs room for every term's bytes plus ten bytes of VBytes per term. `block_offsets`
    receives each block's start, then the total length, which is also written for an empty
    section. Returns the bytes written. Raises ValueError for terms that are not in strictly
    increasing byte order.
    """
    pos: idx = 0
    n: idx = len(ids)
    nblk: idx = 0
    i: idx
    k: idx
    shared: idx
    limit: idx
    start: idx
    length: idx
    prev_start: idx = 0
    prev_len: idx = 0
    for i in range(n):
        start = cython.cast(idx, offsets[ids[i]])
        length = cython.cast(idx, offsets[ids[i] + 1]) - start
        shared = 0
        if i > 0:
            limit = length if length < prev_len else prev_len
            while shared < limit and data[start + shared] == data[prev_start + shared]:
                shared += 1
            if shared == length or (
                shared < prev_len and data[start + shared] < data[prev_start + shared]
            ):
                _bad_term("not after the previous term in byte order", i)
                return 0
            # Back off a partly shared character: the byte at `shared` continues an earlier one.
            while shared > 0 and (data[start + shared] & 0xC0) == 0x80:
                shared -= 1
        if i % block_size == 0:
            block_offsets[nblk] = pos
            nblk += 1
            shared = 0
        else:
            pos = _write_vbyte(out, pos, shared)
        pos = _write_vbyte(out, pos, length - shared)
        for k in range(start + shared, start + length):
            out[pos] = data[k]
            pos += 1
        prev_start = start
        prev_len = length
    block_offsets[nblk] = pos
    return pos


@cython.ccall
@cython.boundscheck(False)
@cython.wraparound(False)
def pack_sequence(values: cython.const[u64][::1], bits: cython.int, out: cython.uchar[::1]) -> idx:
    """Pack each value's low `bits` bits LSB first into `out` (the Log64 layout, the writing side
    of seq_get); `out` needs (len(values) * bits + 7) // 8 bytes. Returns the bytes written."""
    n: idx = len(values)
    if bits == 0 or n == 0:
        return 0
    mask: u64 = _low_mask(bits)
    acc: u64 = 0
    filled: cython.int = 0
    pos: idx = 0
    i: idx
    k: cython.int
    v: u64
    for i in range(n):
        v = values[i] & mask
        acc = (acc | (v << filled)) & _ones()
        if filled + bits >= 64:
            for k in range(8):
                out[pos + k] = cython.cast(cython.uchar, (acc >> (k * 8)) & 0xFF)
            pos += 8
            filled = filled + bits - 64
            acc = v >> (bits - filled) if filled > 0 else 0
        else:
            filled += bits
    k = 0
    while k * 8 < filled:
        out[pos] = cython.cast(cython.uchar, (acc >> (k * 8)) & 0xFF)
        pos += 1
        k += 1
    return pos


_RADIX_MAX_DIGIT = cython.declare(cython.int, 16)


@cython.cfunc
@cython.boundscheck(False)
@cython.wraparound(False)
def _radix_pass(
    key: u64[::1],
    x: u64[::1],
    y: u64[::1],
    key_out: u64[::1],
    x_out: u64[::1],
    y_out: u64[::1],
    shift: cython.int,
    digit_bits: cython.int,
    counts: i64[::1],
) -> cython.bint:
    """One stable counting-sort pass of the rows (key, x, y) by key's digit at `shift`, into the
    `_out` columns. Returns False, writing nothing, when every row has the same digit."""
    n: idx = len(key)
    buckets: idx = cython.cast(idx, 1) << digit_bits
    mask: u64 = _low_mask(digit_bits)
    i: idx
    d: idx
    slot: idx
    for i in range(buckets + 1):
        counts[i] = 0
    for i in range(n):
        counts[cython.cast(idx, (key[i] >> shift) & mask) + 1] += 1
    for i in range(1, buckets + 1):
        if counts[i] == n:
            return False
        counts[i] += counts[i - 1]
    for i in range(n):
        d = cython.cast(idx, (key[i] >> shift) & mask)
        slot = cython.cast(idx, counts[d])
        counts[d] = slot + 1
        key_out[slot] = key[i]
        x_out[slot] = x[i]
        y_out[slot] = y[i]
    return True


@cython.cfunc
@cython.boundscheck(False)
@cython.wraparound(False)
def _unique_rows(
    cs: u64[::1], cp: u64[::1], co: u64[::1], s: u64[::1], p: u64[::1], o: u64[::1]
) -> idx:
    """Copy the sorted rows (cs, cp, co) into (s, p, o), skipping repeats of the row before;
    the two may be the same columns. Returns the rows written."""
    n: idx = len(cs)
    w: idx = 0
    i: idx
    for i in range(n):
        if w > 0 and cs[i] == s[w - 1] and cp[i] == p[w - 1] and co[i] == o[w - 1]:
            continue
        s[w] = cs[i]
        p[w] = cp[i]
        o[w] = co[i]
        w += 1
    return w


@cython.ccall
@cython.boundscheck(False)
@cython.wraparound(False)
def sort_unique_triples(
    s: u64[::1],
    p: u64[::1],
    o: u64[::1],
    scratch: tuple,
    bits: tuple,
) -> idx:
    """Sort the rows (s, p, o) into SPO order and drop repeats, in place; returns how many rows
    remain, at the front of the columns.

    An LSD radix sort: stable passes of up to 16-bit digits over o, then p, then s, ping-ponging
    with `scratch`, three columns as long as the inputs. `bits` gives each column's width
    (s, p, o): values must fit in them.
    """
    n: idx = len(s)
    ts: u64[::1] = scratch[0]
    tp: u64[::1] = scratch[1]
    to: u64[::1] = scratch[2]
    if len(p) != n or len(o) != n or len(ts) < n or len(tp) < n or len(to) < n:
        raise ValueError(f"sort_unique_triples: columns of {n} rows need scratch as long")
    cs: u64[::1] = s
    cp: u64[::1] = p
    co: u64[::1] = o
    swap: u64[::1]
    counts: i64[::1] = _zeroed_i64((1 << _RADIX_MAX_DIGIT) + 1)
    column: cython.int
    width: cython.int
    passes: cython.int
    digit: cython.int
    k: cython.int
    moved: cython.bint
    for column in range(2, -1, -1):
        width = bits[column]
        if width <= 0:
            continue
        passes = (width + _RADIX_MAX_DIGIT - 1) // _RADIX_MAX_DIGIT
        digit = (width + passes - 1) // passes
        for k in range(passes):
            if column == 2:
                moved = _radix_pass(co, cs, cp, to, ts, tp, k * digit, digit, counts)
            elif column == 1:
                moved = _radix_pass(cp, cs, co, tp, ts, to, k * digit, digit, counts)
            else:
                moved = _radix_pass(cs, cp, co, ts, tp, to, k * digit, digit, counts)
            if moved:
                swap = cs
                cs = ts
                ts = swap
                swap = cp
                cp = tp
                tp = swap
                swap = co
                co = to
                to = swap
    return _unique_rows(cs, cp, co, s, p, o)


@cython.final
@cython.auto_pickle(False)
@cython.cclass
class TripleIndex:
    """One HDT's dictionary sections and BitmapTriples, read in place, plus the object (OP) index
    once loaded from a sidecar or built.

    The queries are the generators below:
    predicates are read from the packed Y sequence. Bitmap Y marks the last predicate of each
    subject and bitmap Z the last object of each (subject, predicate) group, so with Java's
    1-based select1(n) and inclusive rank1(i): select1(n) == bm_select1(n - 1) and
    rank1(i) == bm_rank1(i + 1).
    """

    shared: Pfc
    subjects: Pfc
    predicates: Pfc
    objects: Pfc
    n_shared: idx
    n_subjects: idx
    n_predicates: idx
    n_objects: idx
    objects_suffix_coded: cython.bint
    by: cython.const[cython.uchar][::1]
    by_cum: u64[::1]
    bz: cython.const[cython.uchar][::1]
    bz_cum: u64[::1]
    y: cython.const[cython.uchar][::1]
    y_bits: cython.int
    n_y: idx
    z: cython.const[cython.uchar][::1]
    z_bits: cython.int
    n_z: idx
    has_op: cython.bint
    op: cython.const[cython.uchar][::1]
    op_bits: cython.int
    ob: cython.const[cython.uchar][::1]
    ob_cum: u64[::1]
    max_object: idx

    def __init__(self, sections, counts, objects_suffix_coded, bitmap_y, bitmap_z, y, z):
        self.shared, self.subjects, self.predicates, self.objects = sections
        self.n_shared, self.n_subjects, self.n_predicates, self.n_objects = counts
        self.objects_suffix_coded = objects_suffix_coded
        self.by, self.by_cum = bitmap_y
        self.bz, self.bz_cum = bitmap_z
        self.y, self.y_bits, self.n_y = y
        self.z, self.z_bits, self.n_z = z
        self.has_op = False

    def install_op_index(self, op, op_bits: cython.int, ob, ob_cum, max_object: idx):
        """Use this object index: positions into Y grouped by object and sorted by predicate,
        and a bitmap marking where each object's run starts."""
        self.op = op
        self.op_bits = op_bits
        self.ob = ob
        self.ob_cum = ob_cum
        self.max_object = max_object
        self.has_op = True

    @cython.ccall
    def contains(self, s: bytes, p: bytes, o: bytes, o_own: bytes) -> cython.bint:
        """(S, P, O) membership (SPOAdjListsBase.contains)."""
        si: idx = _term_id(self.shared, self.n_shared, self.subjects, self.n_subjects, s, s)
        pi: idx = self.predicates.locate(p) if self.n_predicates > 0 else 0
        oi: idx = _term_id(self.shared, self.n_shared, self.objects, self.n_objects, o, o_own)
        if si == 0 or pi == 0 or oi == 0 or si > _subject_count(self):
            return False
        pidx: idx = _bsearch(self.y, self.y_bits, _y_start(self, si - 1), _y_end(self, si - 1), pi)
        if pidx < 0:
            return False
        return _bsearch(self.z, self.z_bits, _z_start(self, pidx), _z_end(self, pidx), oi) >= 0


# -- positions within the adjacency lists  -----------


@cython.cfunc
@cython.inline
@cython.exceptval(check=False)
def _subject_count(ix: TripleIndex) -> idx:
    return cython.cast(idx, ix.by_cum[len(ix.by_cum) - 1])


@cython.cfunc
@cython.inline
@cython.exceptval(check=False)
def _y_start(ix: TripleIndex, s0: idx) -> idx:
    """First Y position of 0-based subject s0."""
    return 0 if s0 == 0 else bm_select1(ix.by, ix.by_cum, s0 - 1) + 1


@cython.cfunc
@cython.inline
@cython.exceptval(check=False)
def _y_end(ix: TripleIndex, s0: idx) -> idx:
    """One past the last Y position of 0-based subject s0 (boundaryEnd)."""
    if s0 + 1 > _subject_count(ix):
        return ix.n_y
    return bm_select1(ix.by, ix.by_cum, s0) + 1


@cython.cfunc
@cython.inline
@cython.exceptval(check=False)
def _z_start(ix: TripleIndex, y: idx) -> idx:
    """First Z position of the objects for Y position y."""
    return 0 if y == 0 else bm_select1(ix.bz, ix.bz_cum, y - 1) + 1


@cython.cfunc
@cython.inline
@cython.exceptval(check=False)
def _z_end(ix: TripleIndex, y: idx) -> idx:
    """One past the last Z position of the objects for Y position y (boundaryEnd)."""
    if y + 1 > cython.cast(idx, ix.bz_cum[len(ix.bz_cum) - 1]):
        return ix.n_z
    return bm_select1(ix.bz, ix.bz_cum, y) + 1


@cython.cfunc
@cython.inline
@cython.exceptval(check=False)
def _subject_of(ix: TripleIndex, y: idx) -> idx:
    """1-based subject owning Y position y."""
    return bm_rank1(ix.by, ix.by_cum, y) + 1


@cython.cfunc
@cython.exceptval(-2, check=False)
def _bsearch(
    data: cython.const[cython.uchar][::1], bits: cython.int, lo: idx, hi: idx, target: idx
) -> idx:
    """Index in [lo, hi) of the packed sorted run holding target, or -1 (binarySearch)."""
    mid: idx
    v: idx
    while lo < hi:
        mid = (lo + hi) >> 1
        v = seq_get(data, bits, mid)
        if v < target:
            lo = mid + 1
        elif v > target:
            hi = mid
        else:
            return mid
    return -1


# -- term ids and strings ------------------------------------------------------------------------


@cython.cfunc
def _term_id(
    shared: Pfc, n_shared: idx, own: Pfc, n_own: idx, shared_needle: bytes, own_needle: bytes
) -> idx:
    """Global id of a subject or object: shared section first, then its own section; 0 if absent."""
    i: idx
    if n_shared > 0:
        i = shared.locate(shared_needle)
        if i:
            return i
    if n_own > 0:
        i = own.locate(own_needle)
        if i:
            return i + n_shared
    return 0


@cython.cfunc
@cython.inline
def _swap(s: str, offset: idx) -> str:
    """s[offset:] followed by s[:offset]."""
    return s[offset:] + s[:offset]


@cython.ccall
def psfc_encode_if_literal(s: str) -> str:
    """A term as a suffix-coded objects section stores it.

    A typed literal `"v"^^<dt>` becomes `^^<dt>"v"`, split at the last `"^^`. Any other term is
    returned unchanged. Only a term ending in `>` is a typed literal, so a plain or
    language-tagged literal whose raw value contains `"^^` is left alone, where splitting it
    would store a string that decodes to a different term.
    """
    if not (s.startswith('"') and s.endswith(">")):
        return s
    return _swap(s, s.rfind('"^^') + 1)


@cython.ccall
def psfc_decode_if_literal(s: str) -> str:
    """The inverse of psfc_encode_if_literal: `^^<dt>"v"` becomes
    `"v"^^<dt>`, split at the first `"`."""
    if not (s.startswith("^^") and s.endswith('"')):
        return s
    return _swap(s, s.find('"'))


@cython.cfunc
def _subject_str(ix: TripleIndex, s: idx) -> str:
    if s <= ix.n_shared:
        return ix.shared.extract(s)
    return ix.subjects.extract(s - ix.n_shared)


@cython.cfunc
def _object_str(ix: TripleIndex, o: idx) -> str:
    if o <= ix.n_shared:
        return ix.shared.extract(o)
    stored: str = ix.objects.extract(o - ix.n_shared)
    if ix.objects_suffix_coded:
        return psfc_decode_if_literal(stored)
    return stored


# -- queries, yielding PyStringTriple ---------------------


def all_triples(ix: TripleIndex):
    """(?S, ?P, ?O) in SPO order (iterator), walking Y and Z in step."""
    s: idx = 1
    s_str: str = _subject_str(ix, 1) if ix.n_y > 0 else ""
    p: idx
    last_p: idx = 0
    p_str: str = ""
    o: idx
    last_o: idx = 0
    o_str: str = ""
    y: idx
    z: idx = 0
    for y in range(ix.n_y):
        p = seq_get(ix.y, ix.y_bits, y)
        if p != last_p:
            last_p = p
            p_str = ix.predicates.extract(p)
        while z < ix.n_z:
            o = seq_get(ix.z, ix.z_bits, z)
            if o != last_o:
                last_o = o
                o_str = _object_str(ix, o)
            z += 1
            yield _triple(s_str, p_str, o_str)
            if _bit(ix.bz, z - 1):
                break
        if _bit(ix.by, y) and y + 1 < ix.n_y:
            s += 1
            s_str = _subject_str(ix, s)


def subject_triples(ix: TripleIndex, s: str, s_utf8: bytes):
    """(S, ?P, ?O): the subject's triples."""
    si: idx = _term_id(ix.shared, ix.n_shared, ix.subjects, ix.n_subjects, s_utf8, s_utf8)
    if si == 0 or si > _subject_count(ix):
        return
    y: idx
    z: idx
    z_end: idx
    p: idx
    last_p: idx = 0
    p_str: str = ""
    for y in range(_y_start(ix, si - 1), _y_end(ix, si - 1)):
        p = seq_get(ix.y, ix.y_bits, y)
        if p != last_p:
            last_p = p
            p_str = ix.predicates.extract(p)
        z_end = _z_end(ix, y)
        for z in range(_z_start(ix, y), z_end):
            yield _triple(s, p_str, _object_str(ix, seq_get(ix.z, ix.z_bits, z)))


def subject_predicate_triples(ix: TripleIndex, s: str, s_utf8: bytes, p: str, p_utf8: bytes):
    """(S, P, ?O) (querySPX): binary search the subject's predicates, then list the objects."""
    si: idx = _term_id(ix.shared, ix.n_shared, ix.subjects, ix.n_subjects, s_utf8, s_utf8)
    pi: idx = ix.predicates.locate(p_utf8) if ix.n_predicates > 0 else 0
    if si == 0 or pi == 0 or si > _subject_count(ix):
        return
    pidx: idx = _bsearch(ix.y, ix.y_bits, _y_start(ix, si - 1), _y_end(ix, si - 1), pi)
    if pidx < 0:
        return
    z: idx
    for z in range(_z_start(ix, pidx), _z_end(ix, pidx)):
        yield _triple(s, p, _object_str(ix, seq_get(ix.z, ix.z_bits, z)))


def subject_object_triples(
    ix: TripleIndex, s: str, s_utf8: bytes, o: str, o_utf8: bytes, o_own: bytes
):
    """(S, ?P, O) (querySXO): binary search each of the subject's object runs."""
    si: idx = _term_id(ix.shared, ix.n_shared, ix.subjects, ix.n_subjects, s_utf8, s_utf8)
    oi: idx = _term_id(ix.shared, ix.n_shared, ix.objects, ix.n_objects, o_utf8, o_own)
    if si == 0 or oi == 0 or si > _subject_count(ix):
        return
    pidx: idx
    for pidx in range(_y_start(ix, si - 1), _y_end(ix, si - 1)):
        if _bsearch(ix.z, ix.z_bits, _z_start(ix, pidx), _z_end(ix, pidx), oi) >= 0:
            yield _triple(s, ix.predicates.extract(seq_get(ix.y, ix.y_bits, pidx)), o)


def predicate_triples(ix: TripleIndex, p: str, p_utf8: bytes):
    """(?S, P, ?O): scan every predicate in Y, listing the objects of those equal to p."""
    pi: idx = ix.predicates.locate(p_utf8) if ix.n_predicates > 0 else 0
    if pi == 0:
        return
    s: idx = 1
    s_str: str
    y: idx
    z: idx
    for y in range(ix.n_y):
        if seq_get(ix.y, ix.y_bits, y) == pi:
            s_str = _subject_str(ix, s)
            for z in range(_z_start(ix, y), _z_end(ix, y)):
                yield _triple(s_str, p, _object_str(ix, seq_get(ix.z, ix.z_bits, z)))
        if _bit(ix.by, y):
            s += 1


@cython.cfunc
@cython.exceptval(check=False)
def _op_start(ix: TripleIndex, o: idx) -> idx:
    return bm_select1(ix.ob, ix.ob_cum, o - 1)


@cython.cfunc
@cython.exceptval(check=False)
def _op_end(ix: TripleIndex, o: idx) -> idx:
    end: idx = bm_select1(ix.ob, ix.ob_cum, o) if o < ix.max_object else -1
    return ix.n_z if end < 0 else end


def object_triples(ix: TripleIndex, o: str, o_utf8: bytes, o_own: bytes):
    """(?S, ?P, O): the object's run in the object index."""
    oi: idx = _term_id(ix.shared, ix.n_shared, ix.objects, ix.n_objects, o_utf8, o_own)
    if oi == 0 or oi > ix.max_object:
        return
    k: idx
    y: idx
    s: idx
    p: idx
    last_s: idx = 0
    last_p: idx = 0
    s_str: str = ""
    p_str: str = ""
    for k in range(_op_start(ix, oi), _op_end(ix, oi)):
        y = seq_get(ix.op, ix.op_bits, k)
        s = _subject_of(ix, y)
        p = seq_get(ix.y, ix.y_bits, y)
        if s != last_s:
            last_s = s
            s_str = _subject_str(ix, s)
        if p != last_p:
            last_p = p
            p_str = ix.predicates.extract(p)
        yield _triple(s_str, p_str, o)


@cython.cfunc
@cython.exceptval(check=False)
def _bound_by_predicate(ix: TripleIndex, lo: idx, hi: idx, p: idx, upper: cython.bint) -> idx:
    """First index in [lo, hi) of the object index whose predicate is >= p, or > p if `upper`
    (lowerBoundByPredicate / upperBoundByPredicate)."""
    mid: idx
    v: idx
    while lo < hi:
        mid = (lo + hi) >> 1
        v = seq_get(ix.y, ix.y_bits, seq_get(ix.op, ix.op_bits, mid))
        if v < p or (upper and v == p):
            lo = mid + 1
        else:
            hi = mid
    return lo


def predicate_object_triples(
    ix: TripleIndex, p: str, p_utf8: bytes, o: str, o_utf8: bytes, o_own: bytes
):
    """(?S, P, O): binary search the object's run for predicate p."""
    pi: idx = ix.predicates.locate(p_utf8) if ix.n_predicates > 0 else 0
    oi: idx = _term_id(ix.shared, ix.n_shared, ix.objects, ix.n_objects, o_utf8, o_own)
    if pi == 0 or oi == 0 or oi > ix.max_object:
        return
    lo: idx = _op_start(ix, oi)
    hi: idx = _op_end(ix, oi)
    k: idx
    for k in range(
        _bound_by_predicate(ix, lo, hi, pi, False), _bound_by_predicate(ix, lo, hi, pi, True)
    ):
        yield _triple(_subject_str(ix, _subject_of(ix, seq_get(ix.op, ix.op_bits, k))), p, o)


# ---------------------------------------------------------------------------
# Object (OP) index assembly: a stable counting sort by predicate, then by object, in batches.
# Byte compatible with hdt-rs's cached opindex
# ---------------------------------------------------------------------------

_OP_BATCHES = cython.declare(cython.int, 4)


@cython.cfunc
def _too_small(what: str, have: idx, need: idx) -> cython.int:
    raise ValueError(f"object index: {what} holds {have}, needs {need}")


@cython.cfunc
def _bad_groups(n_y: idx) -> cython.int:
    raise ValueError(f"object index: bitmap Z marks more than the {n_y} groups in Y")


@cython.cfunc
def _zeroed_i64(n: idx) -> i64[::1]:
    return memoryview(bytearray(n * 8)).cast("q")


@cython.cfunc
def _zeroed_packed(n: idx, bits: cython.int) -> cython.uchar[::1]:
    """Room for n `bits`-wide entries of a packed sequence."""
    return bytearray((n * bits + 7) >> 3)


@cython.cfunc
@cython.exceptval(check=False)
def _seq_max(data: cython.const[cython.uchar][::1], bits: cython.int, n: idx) -> idx:
    """Largest of the first n entries of a packed sequence, or 0 if n is 0."""
    m: idx = 0
    v: idx
    i: idx
    for i in range(n):
        v = seq_get(data, bits, i)
        if v > m:
            m = v
    return m


@cython.ccall
def scan_max_object(ix: TripleIndex) -> idx:
    """The largest object id in Z, or 0 for an empty graph: sizes assemble_op_index's `start`."""
    return _seq_max(ix.z, ix.z_bits, ix.n_z)


@cython.cfunc
@cython.boundscheck(False)
@cython.wraparound(False)
def _prefix_sum(counts: i64[::1]) -> cython.int:
    """Turn counts shifted up one slot into each bucket's start offset, in place."""
    i: idx
    for i in range(1, len(counts)):
        counts[i] += counts[i - 1]
    return 0


@cython.cfunc
@cython.boundscheck(False)
@cython.wraparound(False)
def _count_objects(ix: TripleIndex, start: i64[::1]) -> cython.int:
    """Count the triples of each object into start[object + 1]."""
    z: idx
    for z in range(ix.n_z):
        start[seq_get(ix.z, ix.z_bits, z) + 1] += 1
    return 0


@cython.cfunc
@cython.boundscheck(False)
@cython.wraparound(False)
@cython.exceptval(check=False)
def _first_object_with_start_at_least(start: i64[::1], max_o: idx, target: idx) -> idx:
    """Smallest object o in [1, max_o + 1] with start[o] >= target (binary search).
    start[max_o + 1] is the triple count, so for any target up to it an answer exists."""
    lo: idx = 1
    hi: idx = max_o + 1
    mid: idx
    while lo < hi:
        mid = (lo + hi) >> 1
        if start[mid] < target:
            lo = mid + 1
        else:
            hi = mid
    return lo


@cython.final
@cython.auto_pickle(False)
@cython.cclass
class _BatchSorter:
    """Sorts the triples of one object range at a time into their slice of `positions`.

    Each range walks Z twice, tracking the Y position of each triple's group (a set bit in bitmap
    Z ends a group): once to count the range's triples per predicate, once to write their
    (Y position, object) pairs into predicate buckets, which leaves each bucket in Y position
    order. Copying the pairs from the buckets in order into their object runs then leaves every
    run in (predicate, Y position) order. Scratch is sized to the range's triples.
    """

    ix: TripleIndex
    start: i64[::1]
    positions: cython.uchar[::1]
    pos_bits: cython.int
    predicate_slots: idx

    @cython.cfunc
    @cython.boundscheck(False)
    @cython.initializedcheck(False)
    @cython.wraparound(False)
    def sort(self, lo: idx, hi: idx) -> cython.int:
        """Sort the triples of objects [lo, hi) into their slice of `positions`."""
        first: idx = cython.cast(idx, self.start[lo])
        n: idx = cython.cast(idx, self.start[hi]) - first
        if n == 0:
            return 0
        ix: TripleIndex = self.ix
        next_slot: i64[::1] = self._predicate_offsets(lo, hi)
        y_buf: cython.uchar[::1] = _zeroed_packed(n, self.pos_bits)
        o_buf: cython.uchar[::1] = _zeroed_packed(n, ix.z_bits)
        self._fill_in_predicate_order(lo, hi, next_slot, y_buf, o_buf)

        cursor: i64[::1] = _zeroed_i64(hi - lo)
        i: idx
        o: idx
        for i in range(hi - lo):
            cursor[i] = self.start[lo + i]
        for i in range(n):
            o = seq_get(o_buf, ix.z_bits, i) - lo
            _seq_set(
                self.positions,
                self.pos_bits,
                cython.cast(idx, cursor[o]),
                seq_get(y_buf, self.pos_bits, i),
            )
            cursor[o] += 1
        return 0

    @cython.cfunc
    @cython.boundscheck(False)
    @cython.initializedcheck(False)
    @cython.wraparound(False)
    def _predicate_offsets(self, lo: idx, hi: idx) -> i64[::1]:
        """Start of each predicate's bucket among the triples whose object is in [lo, hi).

        The bucket array is sized from a scan of Y, so a group past the end of Y is the only way
        an index could fall outside it.
        """
        ix: TripleIndex = self.ix
        next_slot: i64[::1] = _zeroed_i64(self.predicate_slots + 1)
        y: idx = 0
        z: idx
        o: idx
        for z in range(ix.n_z):
            if y >= ix.n_y:
                _bad_groups(ix.n_y)
            o = seq_get(ix.z, ix.z_bits, z)
            if lo <= o < hi:
                next_slot[seq_get(ix.y, ix.y_bits, y) + 1] += 1
            if _bit(ix.bz, z):
                y += 1
        _prefix_sum(next_slot)
        return next_slot

    @cython.cfunc
    @cython.boundscheck(False)
    @cython.initializedcheck(False)
    @cython.wraparound(False)
    def _fill_in_predicate_order(
        self,
        lo: idx,
        hi: idx,
        next_slot: i64[::1],
        y_buf: cython.uchar[::1],
        o_buf: cython.uchar[::1],
    ) -> cython.int:
        """Write the in-range triples' (Y position, object) pairs in (predicate, Y position)
        order."""
        ix: TripleIndex = self.ix
        y: idx = 0
        z: idx
        o: idx
        p: idx
        slot: idx
        for z in range(ix.n_z):
            o = seq_get(ix.z, ix.z_bits, z)
            if lo <= o < hi:
                p = seq_get(ix.y, ix.y_bits, y)
                slot = cython.cast(idx, next_slot[p])
                next_slot[p] = slot + 1
                _seq_set(y_buf, self.pos_bits, slot, y)
                _seq_set(o_buf, ix.z_bits, slot, o)
            if _bit(ix.bz, z):
                y += 1
        return 0


@cython.ccall
def assemble_op_index(
    ix: TripleIndex, start: i64[::1], positions: cython.uchar[::1], pos_bits: cython.int
) -> cython.int:
    """Build the object index into `start` and `positions`.

    `start` must be zeroed and hold scan_max_object(ix) + 2 entries; on return start[o] is where
    object o's run begins and start[max object + 1] is the triple count. `positions` receives one
    `pos_bits`-wide Y position per triple (pos_bits wide enough for any Y position), grouped by
    object and, within a run, ordered by predicate then Y position.

    A two-key stable counting sort (by predicate, then by object) run on one of _OP_BATCHES object
    ranges at a time, each holding about an equal share of the triples, so scratch is a fraction
    of the triple count. Each range's triples fill only its own slice of `positions`.
    """
    n: idx = ix.n_z
    max_o: idx = scan_max_object(ix)
    if len(start) < max_o + 2:
        _too_small("start", len(start), max_o + 2)
    if len(positions) < (n * pos_bits + 7) >> 3:
        _too_small("positions (bytes)", len(positions), (n * pos_bits + 7) >> 3)
    _count_objects(ix, start)
    _prefix_sum(start)

    # __new__ and direct field stores keep pos_bits a C int (no Python constructor arguments).
    sorter: _BatchSorter = _BatchSorter.__new__(_BatchSorter)
    sorter.ix = ix
    sorter.start = start
    sorter.positions = positions
    sorter.pos_bits = pos_bits
    sorter.predicate_slots = _seq_max(ix.y, ix.y_bits, ix.n_y) + 1
    lo: idx = 1
    hi: idx
    b: cython.int
    for b in range(1, _OP_BATCHES + 1):
        hi = max_o + 1
        if b < _OP_BATCHES:
            hi = max(lo, _first_object_with_start_at_least(start, max_o, n * b // _OP_BATCHES))
        sorter.sort(lo, hi)
        lo = hi
    return 0


# ---------------------------------------------------------------------------
# Public result objects
# ---------------------------------------------------------------------------


@cython.final
@cython.auto_pickle(False)
@cython.cclass
class PyStringTriple:
    """A triple of term strings; read-only `subject`, `predicate`, `object` like the PyO3 class."""

    _s: str
    _p: str
    _o: str

    def __init__(self, subject: str, predicate: str, obj: str):
        self._s = subject
        self._p = predicate
        self._o = obj

    @property
    def subject(self) -> str:
        return self._s

    @property
    def predicate(self) -> str:
        return self._p

    @property
    def object(self) -> str:
        return self._o

    def __repr__(self) -> str:
        return f"PyStringTriple({self._s!r}, {self._p!r}, {self._o!r})"


@cython.cfunc
@cython.inline
def _triple(s: str, p: str, o: str) -> PyStringTriple:
    # __new__ skips __init__'s argument parsing; this runs once per result triple.
    t: PyStringTriple = PyStringTriple.__new__(PyStringTriple)
    t._s = s
    t._p = p
    t._o = o
    return t
