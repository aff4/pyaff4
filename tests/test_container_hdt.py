#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

"""information.hdt and information.hdt.opidx, written next to information.turtle on close."""

import os
import tempfile
import unittest
import zipfile as stdlib_zip

import rdflib

from pyaff4 import container, data_store, rdfvalue, zip
from pyhdt2_cython import PyHdt
from pyhdt2_cython.hdt import Hdt
from rdflib_hdt_ng.rdflib_bridge import _term_str
from rdflib_hdt_ng.union_store import HdtUnionStore
from tests.test_reopened_writes import CERT

HDT = "information.hdt"
OPIDX = "information.hdt.opidx"
TURTLE = "information.turtle"


class ContainerHdtTests(unittest.TestCase):
    path = os.path.join(tempfile.gettempdir(), "aff4_container_hdt.aff4")
    other_path = os.path.join(tempfile.gettempdir(), "aff4_container_hdt_other.aff4")

    def setUp(self):
        self.urn = rdfvalue.URN.FromFileName(self.path)
        for path in (self.path, self.other_path):
            if os.path.exists(path):
                os.unlink(path)
            self.addCleanup(lambda p=path: os.path.exists(p) and os.unlink(p))

    def create(self, name, data, encrypted=False, path=None):
        urn = self.urn if path is None else rdfvalue.URN.FromFileName(path)
        with data_store.MemoryDataStore() as resolver:
            with container.Container.createURN(resolver, urn, encryption=encrypted) as volume:
                logical = volume
                if encrypted:
                    volume.setPassword("password")
                    volume.setPublicKeyCert(CERT)
                    logical = volume.getChildContainer()
                with logical.newLogicalStream(name, len(data)) as stream:
                    stream.Write(data)

    def append(self, name, data):
        with container.Container.openURNtoContainer(self.urn, mode="+") as volume:
            with volume.newLogicalStream(name, len(data)) as stream:
                stream.Write(data)

    def members(self, path=None):
        with stdlib_zip.ZipFile(self.path if path is None else path) as z:
            return {info.filename: z.read(info) for info in z.infolist()}

    @staticmethod
    def turtle_terms(members):
        turtle = rdflib.Graph().parse(data=members[TURTLE].decode("utf-8"), format="turtle")
        return {tuple(_term_str(t) for t in triple) for triple in turtle}

    def assert_hdt_matches_turtle(self, members):
        from_turtle = self.turtle_terms(members)
        hdt = PyHdt(members[HDT])
        from_hdt = {(t.subject, t.predicate, t.object) for t in hdt.triples()}
        self.assertEqual(from_hdt, from_turtle)
        self.assertEqual(len(hdt), len(from_hdt))

    def test_new_container_holds_hdt_and_object_index(self):
        self.create("hello", b"hello world")
        members = self.members()
        self.assertIn(HDT, members)
        self.assert_hdt_matches_turtle(members)
        self.assertEqual(Hdt(members[HDT], members[OPIDX]).sidecar_status, {"opidx": "used"})

    def test_windows_path_is_stored_raw_and_read_back_from_the_hdt(self):
        # Backslashes before n and t, and quotes: escaping on either side would change the name.
        name = 'C:\\Users\\new\\tab "quoted".txt'
        self.create(name, b"data")
        members = self.members()
        self.assert_hdt_matches_turtle(members)
        self.assertIn(f'"{name}"', {t.object for t in PyHdt(members[HDT]).triples()})
        with container.Container.openURNtoContainer(self.urn) as volume:
            self.assertIsInstance(volume.resolver.store.store, HdtUnionStore)
            self.assertEqual([i.pathName for i in volume.images()], [name])

    def test_append_regenerates_hdt_with_every_triple(self):
        self.create("first", b"one")
        self.append("second", b"two")
        members = self.members()
        self.assert_hdt_matches_turtle(members)
        self.assertEqual(Hdt(members[HDT], members[OPIDX]).sidecar_status, {"opidx": "used"})
        with container.Container.openURNtoContainer(self.urn) as volume:
            self.assertIsInstance(volume.resolver.store.store, HdtUnionStore)
            self.assertEqual(sorted(i.pathName for i in volume.images()), ["first", "second"])

    def test_read_only_open_reads_the_hdt_and_write_open_the_turtle(self):
        self.create("hello", b"hello world")
        with container.Container.openURNtoContainer(self.urn) as volume:
            self.assertIsInstance(volume.resolver.store.store, HdtUnionStore)
            self.assertEqual([i.pathName for i in volume.images()], ["hello"])
        with container.Container.openURNtoContainer(self.urn, mode="+") as volume:
            self.assertNotIsInstance(volume.resolver.store.store, HdtUnionStore)

    def test_one_resolver_reads_several_hdt_containers(self):
        self.create("first", b"one")
        self.create("second", b"two", path=self.other_path)
        expected = self.turtle_terms(self.members()) | self.turtle_terms(
            self.members(self.other_path)
        )
        other_urn = rdfvalue.URN.FromFileName(self.other_path)
        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, None, self.urn) as first_zip:
                with container.ZipMemberContainer(resolver, None, first_zip):
                    with zip.ZipFile.NewZipFile(resolver, None, other_urn) as second_zip:
                        with container.ZipMemberContainer(resolver, None, second_zip):
                            self.assertIsInstance(resolver.store.store, HdtUnionStore)
                            got = {tuple(_term_str(t) for t in triple) for triple in resolver.store}
                            self.assertEqual(got, expected)

    def test_encrypted_containers_have_no_hdt(self):
        self.create("hello", b"hello world", encrypted=True)
        self.assertNotIn(HDT, self.members())
        with container.Container.openURNtoContainer(self.urn) as volume:
            volume.setPassword("password")
            inner = volume.getChildContainer()
            self.assertFalse(inner.zip_file.ContainsSegment(HDT))
            self.assertEqual([i.pathName for i in inner.images()], ["hello"])


if __name__ == "__main__":
    unittest.main()
