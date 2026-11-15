# Copyright 2015 Google Inc. All rights reserved.
# Copyright © 2026 Apple Inc.
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
import os
import io
import unittest
import tempfile

from pyaff4.aff4 import newARN
from pyaff4 import data_store
from pyaff4 import lexicon
from pyaff4 import plugins
from pyaff4 import rdfvalue
from pyaff4 import zip
from pyaff4 import version, hexdump

from rdflib.term import Literal

class ZipTest(unittest.TestCase):
    filename = tempfile.gettempdir() + "/aff4_ziptest.zip"
    filename_urn = rdfvalue.URN.FromFileName(filename)
    segment_name = "Foobar.txt"
    streamed_segment = "streamed.txt"
    data1 = b"I am a segment!"
    data2 = b"I am another segment!"

    def setUp(self):
        try:
            os.unlink(self.filename)
        except (IOError, OSError):
            pass
        
        with data_store.MemoryDataStore() as resolver:
            # resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
            #              Literal("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version.aff4v10, self.filename_urn, appendmode="truncate") as zip_file:
                #self.volume_urn = zip_file.urn
                #segment_urn = self.volume_urn.Append(self.segment_name)

                with zip_file.CreateZipSegment(self.segment_name) as segment:
                    segment.Write(self.data1)

                with zip_file.CreateZipSegment(self.segment_name) as segment2:
                    segment2.SeekWrite(0, 2)
                    segment2.Write(self.data2)

                #streamed_urn = self.volume_urn.Append(self.streamed_segment)
                with zip_file.CreateZipSegment(self.streamed_segment) as streamed:
                    streamed.compression_method = zip.ZIP_DEFLATE
                    src = io.BytesIO(self.data1)
                    streamed.WriteStream(src)

    def tearDown(self):
        try:
            os.unlink(self.filename)
        except (IOError, OSError):
            pass

    def testStreamedSegment(self):
        resolver = data_store.MemoryDataStore()

        # This is required in order to load and parse metadata from this volume
        # into a fresh empty resolver.
        with zip.ZipFile.NewZipFile(resolver, version.aff4v10, self.filename_urn) as zip_file:
            #segment_urn = zip_file.urn.Append(self.streamed_segment)

            with zip_file.OpenZipSegment(self.streamed_segment) as segment:
                self.assertEqual(segment.Read(1000), self.data1)

    def testOpenSegmentByURN(self):
        resolver = data_store.MemoryDataStore()

        # This is required in order to load and parse metadata from this volume
        # into a fresh empty resolver.
        with zip.ZipFile.NewZipFile(resolver, version.aff4v10, self.filename_urn) as zip_file:
            #segment_urn = zip_file.urn.Append(self.segment_name)

            with zip_file.OpenZipSegment(self.segment_name) as segment:
                self.assertEqual(segment.Read(1000), self.data1 + self.data2)
        # with resolver.AFF4FactoryOpen(segment_urn) as segment:
        #     self.assertEqual(segment.Read(1000), self.data1 + self.data2)

    def testSeekThrowsWhenWriting(self):
        resolver = data_store.MemoryDataStore()
        # resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
        #              Literal("truncate"))

        with zip.ZipFile.NewZipFile(resolver, version.aff4v10, self.filename_urn, appendmode="truncate") as zip_file:
            segment_urn = zip_file.urn.Append(self.streamed_segment)

            with zip_file.CreateMember(segment_urn) as segment:
                try:
                    segment.SeekWrite(100,0)
                    segment.Write("foo")
                    hexdump.hexdump(segment.fd.getvalue())
                    segment.SeekWrite(0, 0)
                    segment.Write("bar")
                    hexdump.hexdump(segment.fd.getvalue())
                    self.fail("Seeking when writing not supported")
                except:
                    pass


class Zip64ExtraFieldTest(unittest.TestCase):
    def testInstancesDoNotShareFieldValues(self):
        first = zip.Zip64FileHeaderExtensibleField()
        first.Set("file_size", 5)
        second = zip.Zip64FileHeaderExtensibleField()
        self.assertEqual(5, first.Get("file_size"))
        self.assertIsNone(second.Get("file_size"))
        self.assertTrue(second.empty())


if __name__ == '__main__':
    unittest.main()
