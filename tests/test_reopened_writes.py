#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""Writes to streams already stored in a container that is reopened for writing.

A container reopened with mode "+" (appendmode "random") must either store a write correctly or
refuse it with an IOError. It must never accept a write and then lose it, or damage stored data:
- a stored (uncompressed) ZIP member can be rewritten in place within its size, and its CRC-32
  is updated wherever it is recorded;
- a compressed ZIP member, and an image stream with stored data, are read-only once reopened.
"""

import io
import os
import struct
import tempfile
import unittest
import zipfile as stdlib_zip
import zlib

from pyaff4 import container, data_store, rdfvalue, zip
from pyaff4.version import Version

KEYS = os.path.join(os.path.dirname(__file__), "..", "test_images", "keys")
CERT = os.path.join(KEYS, "certificate.pem")
PRIVATE_KEY = os.path.join(KEYS, "key.pem")
SMALL = 137  # size hint: the stream is a compressed ZIP member
LARGE = 10_000_000  # size hint: the stream is an AFF4 image stream


class ReopenedStreamWriteTests(unittest.TestCase):
    path = os.path.join(tempfile.gettempdir(), "aff4_reopened_stream_writes.aff4")

    def setUp(self):
        self.urn = rdfvalue.URN.FromFileName(self.path)
        if os.path.exists(self.path):
            os.unlink(self.path)
        self.addCleanup(lambda: os.path.exists(self.path) and os.unlink(self.path))

    def child(self, volume, encrypted, creating):
        if not encrypted:
            return volume
        if creating:
            volume.setPassword("password")
            volume.setPublicKeyCert(CERT)
        else:
            volume.setPrivateKey(PRIVATE_KEY)
        return volume.getChildContainer()

    def create(self, encrypted, size_hint, data):
        with data_store.MemoryDataStore() as resolver:
            with container.Container.createURN(resolver, self.urn, encryption=encrypted) as volume:
                logical = self.child(volume, encrypted, creating=True)
                with logical.newLogicalStream("hello", size_hint) as stream:
                    stream.Write(data)

    def write_after_reopen(self, encrypted, offset, data):
        with container.Container.openURNtoContainer(self.urn, mode="+") as volume:
            logical = self.child(volume, encrypted, creating=False)
            images = list(logical.images())
            with logical.resolver.AFF4FactoryOpen(images[0].urn) as stream:
                stream.SeekWrite(offset, 0)
                stream.Write(data)

    def read_back(self, encrypted):
        with container.Container.openURNtoContainer(self.urn) as volume:
            logical = self.child(volume, encrypted, creating=False)
            images = list(logical.images())
            with logical.resolver.AFF4FactoryOpen(images[0].urn) as stream:
                return stream.Read(4096)

    def test_writes_to_stored_streams_are_refused_and_leave_data_intact(self):
        original = b"a" * 512
        for encrypted in (False, True):
            for size_hint in (SMALL, LARGE):
                for offset in (0, 512):  # rewrite inside the stream, then append at its end
                    with self.subTest(encrypted=encrypted, size_hint=size_hint, offset=offset):
                        self.create(encrypted, size_hint, original)
                        with self.assertRaisesRegex(IOError, "read only"):
                            self.write_after_reopen(encrypted, offset, b"b" * 512)
                        self.assertEqual(self.read_back(encrypted), original)

    def listing(self, encrypted):
        with container.Container.openURNtoContainer(self.urn) as volume:
            logical = self.child(volume, encrypted, creating=False)
            result = {}
            for image in logical.images():
                with logical.resolver.AFF4FactoryOpen(image.urn) as stream:
                    result[image.pathName] = stream.Read(100)
            return result

    def turtle_members(self, encrypted):
        with container.Container.openURNtoContainer(self.urn) as volume:
            logical = self.child(volume, encrypted, creating=False)
            zip_file = logical.zip if hasattr(logical, "zip") else logical.zip_file
            return sorted(n for n in zip_file.members if n.startswith("information.turtle"))

    def test_repeated_appends_keep_every_file(self):
        # Each append rewrites the container's information.turtle as one member ("latest"
        # mode), for an encrypted container's inner zip as for a plain container.
        for encrypted in (False, True):
            with self.subTest(encrypted=encrypted):
                self.setUp()
                self.create(encrypted, SMALL, b"data0")
                for n in range(1, 4):
                    with container.Container.openURNtoContainer(self.urn, mode="+") as volume:
                        logical = self.child(volume, encrypted, creating=False)
                        with logical.newLogicalStream(f"file{n}", SMALL) as stream:
                            stream.Write(f"data{n}".encode())
                    expected = {"hello": b"data0"}
                    expected.update({f"file{k}": f"data{k}".encode() for k in range(1, n + 1)})
                    self.assertEqual(self.listing(encrypted), expected, f"after append {n}")
                    self.assertEqual(self.turtle_members(encrypted), ["information.turtle"])


class CompressedMemberRecreateTests(unittest.TestCase):
    path = os.path.join(tempfile.gettempdir(), "aff4_compressed_member_recreate.zip")
    version = Version(1, 1, "pyaff4")

    def setUp(self):
        self.urn = rdfvalue.URN.FromFileName(self.path)
        if os.path.exists(self.path):
            os.unlink(self.path)
        self.addCleanup(lambda: os.path.exists(self.path) and os.unlink(self.path))
        self.replace(b"original", mode="truncate", remove_first=False)

    def replace(self, data, mode, remove_first):
        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, self.version, self.urn, appendmode=mode) as zf:
                if remove_first:
                    zf.RemoveSegment("foo")
                with zf.CreateZipSegment("foo") as segment:
                    segment.compression_method = zip.ZIP_DEFLATE
                    segment.Write(data)
                    segment.Flush()

    def content(self):
        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, self.version, self.urn) as zf:
                with zf.OpenZipSegment("foo") as segment:
                    return segment.Read(100)

    def test_recreating_an_existing_compressed_member_refuses_writes(self):
        with self.assertRaisesRegex(IOError, "read only"):
            self.replace(b"replaced", mode="random", remove_first=False)
        self.assertEqual(self.content(), b"original")

    def test_removing_the_member_first_replaces_it(self):
        self.replace(b"replaced", mode="random", remove_first=True)
        self.assertEqual(self.content(), b"replaced")


class StoredZipMemberRewriteTests(unittest.TestCase):
    path = os.path.join(tempfile.gettempdir(), "aff4_stored_member_rewrite.zip")
    version = Version(1, 1, "pyaff4")

    def setUp(self):
        self.urn = rdfvalue.URN.FromFileName(self.path)
        if os.path.exists(self.path):
            os.unlink(self.path)
        self.addCleanup(lambda: os.path.exists(self.path) and os.unlink(self.path))
        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(
                resolver, self.version, self.urn, appendmode="truncate"
            ) as zip_file:
                for name, data in (("foo", b"abcdefghijk"), ("bar", b"lmnopqrstuv")):
                    with zip_file.CreateZipSegment(name) as segment:
                        segment.compression_method = zip.ZIP_STORED
                        segment.Write(data)
                        segment.Flush()

    def write(self, offset, data):
        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(
                resolver, self.version, self.urn, appendmode="random"
            ) as zip_file:
                with zip_file.OpenZipSegment("foo") as segment:
                    segment.SeekWrite(offset, 0)
                    segment.Write(data)

    def members(self):
        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, self.version, self.urn) as zip_file:
                result = {}
                for name in ("foo", "bar"):
                    with zip_file.OpenZipSegment(name) as segment:
                        result[name] = segment.Read(100)
                return result

    def test_rewrite_within_the_member_is_stored(self):
        self.write(2, b"0000")
        self.assertEqual(self.members(), {"foo": b"ab0000ghijk", "bar": b"lmnopqrstuv"})

    def test_rewrites_keep_every_crc_valid_without_moving_bytes(self):
        size = os.stat(self.path).st_size
        self.write(2, b"0000")
        self.write(0, b"Z")
        self.assertEqual(os.stat(self.path).st_size, size)
        self.assertEqual(recorded_crcs(self.path, "foo"), [zlib.crc32(b"Zb0000ghijk")] * 3)
        self.assertEqual(stdlib_zip.ZipFile(self.path).testzip(), None)

    def test_writes_past_the_member_end_are_refused_and_leave_neighbours_intact(self):
        for offset, data in ((11, b"XYZ"), (9, b"XYZ"), (0, b"z" * 12)):
            with self.subTest(offset=offset, length=len(data)):
                with self.assertRaisesRegex(IOError, "exceeds the existing ZIP segment"):
                    self.write(offset, data)
                self.assertEqual(self.members(), {"foo": b"abcdefghijk", "bar": b"lmnopqrstuv"})


class _Unseekable(io.RawIOBase):
    """Write-only file wrapper; zipfile writes data descriptors when it cannot seek back."""

    def __init__(self, f):
        self.f = f

    def writable(self):
        return True

    def write(self, b):
        return self.f.write(b)


class DataDescriptorMemberTests(unittest.TestCase):
    path = os.path.join(tempfile.gettempdir(), "aff4_descriptor_member.zip")

    def setUp(self):
        self.addCleanup(lambda: os.path.exists(self.path) and os.unlink(self.path))
        with open(self.path, "wb") as f:
            with stdlib_zip.ZipFile(_Unseekable(f), "w", stdlib_zip.ZIP_STORED) as z:
                z.writestr("foo", b"abcdefghijk")
                z.writestr("bar", b"lmnopqrstuv")

    def test_rewrite_updates_the_descriptor_and_directory_crc(self):
        self.assertEqual(local_header(self.path, "foo")["flags"] & 0x8, 0x8)
        urn = rdfvalue.URN.FromFileName(self.path)
        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(
                resolver, Version(1, 1, "pyaff4"), urn, appendmode="random"
            ) as zip_file:
                with zip_file.OpenZipSegment("foo") as segment:
                    segment.SeekWrite(2, 0)
                    segment.Write(b"0000")
        self.assertEqual(recorded_crcs(self.path, "foo"), [zlib.crc32(b"ab0000ghijk")] * 3)
        archive = stdlib_zip.ZipFile(self.path)
        self.assertEqual(archive.testzip(), None)
        self.assertEqual(archive.read("bar"), b"lmnopqrstuv")


def local_header(path, name):
    """The member's local file header fields and data, parsed from the raw bytes."""
    info = stdlib_zip.ZipFile(path).getinfo(name)
    with open(path, "rb") as f:
        raw = f.read()
    start = info.header_offset
    flags, crc = (
        struct.unpack("<H", raw[start + 6 : start + 8])[0],
        struct.unpack("<I", raw[start + 14 : start + 18])[0],
    )
    name_len, extra_len = struct.unpack("<HH", raw[start + 26 : start + 30])
    data_start = start + 30 + name_len + extra_len
    data_end = data_start + info.compress_size
    return {"flags": flags, "crc": crc, "data": raw[data_start:data_end], "rest": raw[data_end:]}


def recorded_crcs(path, name):
    """[CRC-32 of the stored data, CRC in the central directory, CRC in the local header or its
    data descriptor], read independently of pyaff4."""
    header = local_header(path, name)
    if header["flags"] & 0x8 and header["crc"] == 0:
        rest = header["rest"]
        offset = 4 if rest[:4] == b"PK\x07\x08" else 0
        local = struct.unpack("<I", rest[offset : offset + 4])[0]
    else:
        local = header["crc"]
    directory = stdlib_zip.ZipFile(path).getinfo(name).CRC
    return [zlib.crc32(header["data"]), directory, local]


if __name__ == "__main__":
    unittest.main()
