# -*- coding: utf-8 -*-
# Copyright 2018-2019 Schatz Forensic Pty Ltd All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.
#
# Author: Bradley L Schatz bradley@evimetry.com

from __future__ import unicode_literals
import tempfile

from future import standard_library
standard_library.install_aliases()
import os
import unittest

from pyaff4 import data_store, escaping
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import zip
from pyaff4.version import Version
import traceback

class ZipTest(unittest.TestCase):
    filename = tempfile.gettempdir() + u"/aff4_zip_extended_test.zip"
    filename_urn = rdfvalue.URN.FromFileName(filename)
    data1 = b"I am a plain old segment!!!"
    data2 = b"I am an overwritten segment"
    segment_name = "foo"

    #@unittest.skip
    def testRemoveDoesntRewindForNonLastSegment(self):
        try:
            os.unlink(self.filename)
        except (IOError, OSError):
            pass

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, Version(1, 1, "pyaff4"), self.filename_urn) as zip_container:
                self.volume_urn = zip_container.urn

                with zip_container.CreateZipSegment("foo") as segment:
                    segment.Write(self.data1)
                    segment.Flush()

                with zip_container.CreateZipSegment("bar") as segment:
                    segment.Write(self.data1)
                    segment.Flush()

                backing_store_urn = resolver.GetUnique(lexicon.transient_graph, self.volume_urn, lexicon.AFF4_STORED)
                with resolver.AFF4FactoryOpen(backing_store_urn) as backing_store:
                    print()
                    self.assertEquals(93, backing_store.writeptr)

                try:
                    zip_container.RemoveSegment("foo")
                    self.fail()
                except:
                    pass

        self.assertEquals(687, os.stat(self.filename).st_size)

    #@unittest.skip
    def testEditInplaceZip(self):
        try:
            os.unlink(self.filename)
        except (IOError, OSError):
            pass

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, Version(1, 1, "pyaff4"), self.filename_urn) as zip_container:
                self.volume_urn = zip_container.urn

                with zip_container.CreateZipSegment("foo") as segment:
                    segment.compression_method = zip.ZIP_STORED
                    segment.Write(b'abcdefghijk')
                    segment.Flush()

                with zip_container.CreateZipSegment("bar") as segment:
                    segment.compression_method = zip.ZIP_STORED
                    segment.Write(b'alkjflajdflaksjdadflkjd')
                    segment.Flush()

                backing_store_urn = resolver.GetUnique(lexicon.transient_graph, self.volume_urn, lexicon.AFF4_STORED)
                with resolver.AFF4FactoryOpen(backing_store_urn) as backing_store:
                    print()

        self.assertEquals(716, os.stat(self.filename).st_size)


        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("random"))

            with zip.ZipFile.NewZipFile(resolver, Version(1, 1, "pyaff4"), self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn

                with zip_file.OpenZipSegment("foo") as segment:
                    segment.SeekWrite(0,0)
                    segment.Write(b'0000')

        self.assertEquals(716, os.stat(self.filename).st_size)

    #@unittest.skip
    def testRemoveDoesRewind(self):
        try:
            os.unlink(self.filename)
        except (IOError, OSError):
            pass

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, Version(1, 1, "pyaff4"), self.filename_urn) as zip_container:
                self.volume_urn = zip_container.urn

                with zip_container.CreateZipSegment("foo") as segment:
                    segment.Write(self.data1)
                    segment.Flush()

                with zip_container.CreateZipSegment("bar") as segment:
                    segment.Write(self.data1)
                    segment.Flush()

                backing_store_urn = resolver.GetUnique(lexicon.transient_graph, self.volume_urn, lexicon.AFF4_STORED)
                with resolver.AFF4FactoryOpen(backing_store_urn) as backing_store:
                    print()
                    self.assertEquals(93, backing_store.writeptr)

                zip_container.RemoveSegment("bar")

                with zip_container.CreateZipSegment("nar") as segment:
                    segment.Write(self.data2)
                    segment.Flush()

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("append"))

            with zip.ZipFile.NewZipFile(resolver, Version(1, 1, "pyaff4"), self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                segment_urn = self.volume_urn.Append(escaping.arnPathFragment_from_path(self.segment_name),
                                                     quote=False)
                self.assertFalse(zip_file.ContainsSegment("bar"))
                self.assertTrue(zip_file.ContainsSegment("foo"))
                self.assertTrue(zip_file.ContainsSegment("nar"))

                with zip_file.OpenZipSegment("foo") as segment:
                    self.assertEquals(self.data1, segment.Read(len(self.data1)))

                with zip_file.OpenZipSegment("nar") as segment:
                    self.assertEquals(self.data2, segment.Read(len(self.data2)))

        self.assertEquals(736, os.stat(self.filename).st_size)

    #@unittest.skip
    def testRemoveIsEmpty(self):
        try:
            os.unlink(self.filename)
        except (IOError, OSError):
            pass

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, Version(1, 1, "pyaff4"), self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                segment_urn = self.volume_urn.Append(escaping.arnPathFragment_from_path(self.segment_name), quote=False)

                with zip_file.CreateMember(segment_urn) as segment:
                    segment.Write(self.data1)
                    segment.Flush()

                zip_file.RemoveMember(segment_urn)

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("append"))

            with zip.ZipFile.NewZipFile(resolver, Version(1, 1, "pyaff4"), self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                segment_urn = self.volume_urn.Append(escaping.arnPathFragment_from_path(self.segment_name),
                                                     quote=False)
                self.assertFalse(zip_file.ContainsMember(segment_urn))

        self.assertEquals(518, os.stat(self.filename).st_size)

    #@unittest.skip
    def testRemoveThenReAdd(self):
        try:
            os.unlink(self.filename)
        except (IOError, OSError):
            pass
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, Version(1, 1, "pyaff4"), self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                segment_urn = self.volume_urn.Append(escaping.arnPathFragment_from_path(self.segment_name), quote=False)

                with zip_file.CreateMember(segment_urn) as segment:
                    segment.Write(self.data1)
                    segment.Flush()

                zip_file.RemoveMember(segment_urn)

                with zip_file.CreateMember(segment_urn) as segment:
                    segment.Write(self.data2)


        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, Version(1, 1, "pyaff4"), self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                segment_urn = self.volume_urn.Append(escaping.arnPathFragment_from_path(self.segment_name),
                                                     quote=False)
                self.assertTrue(zip_file.ContainsMember(segment_urn))

                with zip_file.OpenMember(segment_urn) as segment:
                    self.assertEquals(self.data2, segment.Read(len(self.data2)))

        self.assertEquals(629, os.stat(self.filename).st_size)

if __name__ == '__main__':
    unittest.main()
