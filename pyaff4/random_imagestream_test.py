from __future__ import unicode_literals
# Copyright 2019 Schatz Forensic Pty. Ltd. All rights reserved.
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
import tempfile

from future import standard_library
standard_library.install_aliases()

import unittest
import os

from pyaff4 import aff4_image
from pyaff4 import data_store
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import zip
from pyaff4 import container
from pyaff4 import plugins


class AFF4ImageTest(unittest.TestCase):
    filename = tempfile.gettempdir() + u"/aff4_test_random.zip"
    filename_urn = rdfvalue.URN.FromFileName(filename)
    image_name = "image.dd"

    def tearDown(self):
        try:
            os.unlink(self.filename)
            pass
        except (IOError, OSError):
            pass

    #@unittest.skip
    def testLimitBufferOnlyStreamToOneChunk2(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b"abcd")
                    image.Trim(2)

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.SeekRead(0, 0)
                    res = image.ReadAll()
                    self.assertEqual(b"ab", res)

    #@unittest.skip
    def testLimitBufferOnlyStreamToOneChunk(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b"abcd")
                    image.Trim(3)

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.SeekRead(0, 0)
                    res = image.ReadAll()
                    self.assertEqual(b"abc", res)

    #@unittest.skip
    def testLimitBufferOnlyStream(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b"ab")
                    image.Trim(1)
                    self.assertEquals(1, image.size)

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.SeekRead(0, 0)
                    res = image.ReadAll()
                    self.assertEqual(b"a", res)

    #@unittest.skip
    def testBevyOneThenRewriteInEarlierChunkThenLaterChunk(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b"abcdef")

                    image.SeekWrite(1, 0)
                    image.Write(b"00")

                    image.SeekWrite(6, 0)
                    image.Write(b"h")


        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.SeekRead(0, 0)
                    res = image.Read(7)
                    self.assertEqual(b"a00defh", res)

    #@unittest.skip
    def testBevyPlusOneThenRewriteInEarlierChunkThenLaterChunk(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b"abcdefg")

                    image.SeekWrite(1, 0)
                    image.Write(b"00")

                    image.SeekWrite(7, 0)
                    image.Write(b"h")


        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.SeekRead(0, 0)
                    res = image.Read(8)
                    self.assertEqual(b"a00defgh", res)


    #@unittest.skip
    def testBigForwardBevySkipThreePriorWritten(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 2
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b'bzm')
                    image.SeekWrite(8,0)
                    image.Write(b'a')


        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    self.assertEqual(b"bzm\0\0\0\0\0a", image.ReadAll())

    #@unittest.skip
    def testBigForwardBevySkipTwoPriorWritten(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 2
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b'bz')
                    image.SeekWrite(8,0)
                    image.Write(b'a')


        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    self.assertEqual(b"bz\0\0\0\0\0\0a", image.ReadAll())

    #@unittest.skip
    def testBigForwardBevySkipSinglePriorWritten(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 2
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b'b')
                    image.SeekWrite(8,0)
                    image.Write(b'a')


        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    self.assertEqual(b"b\0\0\0\0\0\0\0a", image.ReadAll())

    #@unittest.skip
    def testBigForwardBevySkipNoPriorWritten(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 2
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.SeekWrite(8,0)
                    image.Write(b'a')


        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    self.assertEqual(b"\0\0\0\0\0\0\0\0a", image.ReadAll())

    #@unittest.skip
    def testTwoChunksFirstChunkThenEndOfSecondChunk(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 2
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b"abcd")
                    image.SeekWrite(0,0)
                    image.Write(b'z')
                    image.SeekWrite(4,0)
                    image.Write(b'q')


        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    self.assertEqual(b"zbcdq", image.ReadAll())


    #@unittest.skip
    def testRewriteInEarlierBevvyCrossBevvy(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 5
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b"abcdefghijklmnopqrst0123456789!!")

                    image.SeekWrite(8, 0)
                    image.Write(b"0000")


        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.SeekRead(7, 0)
                    res = image.Read(6)
                    self.assertEqual(b"h0000m", res)

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    self.assertEqual(b"abcdefgh0000mnopqrst0123456789!!", image.ReadAll())

    #@unittest.skip
    def testRewriteInEarlierBevvyCrossChunk(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 5
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b"abcdefghijlmnopq")

                    image.SeekWrite(4, 0)
                    image.Write(b"00")


        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.SeekRead(0, 0)
                    res = image.Read(8)
                    self.assertEqual(b"abcd00gh", res)

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    self.assertEqual(b"abcd00ghijlmnopq", image.ReadAll())

    #@unittest.skip
    def testRewriteInEarlierBevvy(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 5
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b"abcdefghijlmnopq")

                    image.SeekWrite(1, 0)
                    image.Write(b"000")


        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.SeekRead(0, 0)
                    res = image.Read(5)
                    self.assertEqual(b"a000e", res)

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    self.assertEqual(b"a000efghijlmnopq", image.ReadAll())

    #@unittest.skip
    def testRewriteInEarlierChunk(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 10
                    image.chunks_per_segment = 3
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b"abcdeabcdeabcdeabcde")

                    image.SeekWrite(1, 0)
                    image.Write(b"000")


        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.SeekRead(0, 0)
                    res = image.Read(5)
                    self.assertEqual(b"a000e", res)

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    self.assertEqual(b"a000eabcdeabcdeabcde", image.ReadAll())

    #@unittest.skip
    def testRewriteWithinChunk(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 10
                    image.chunks_per_segment = 3
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.SeekWrite(0, 0)
                    image.Write(b"abcd")

                    image.SeekWrite(1, 0)
                    image.Write(b"ef")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.SeekRead(0, 0)
                    res = image.Read(4)
                    self.assertEqual(b"aefd", res)

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    self.assertEqual(b"aefd", image.ReadAll())

    #@unittest.skip
    def testPartialWriteAcrossTwoChunks(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 10
                    image.chunks_per_segment = 3
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    image.SeekWrite(8, 0)
                    image.Write(b"abcd")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.SeekRead(8, 0)
                    res = image.Read(4)
                    self.assertEqual(b"abcd", res)


    #@unittest.skip
    def testPartialWriteAtTwoOffset(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 10
                    image.chunks_per_segment = 3
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    image.SeekWrite(2, 0)
                    image.Write(b"ab")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    res = image.Read(4)
                    self.assertEqual(b"\0\0ab", res)

    #@unittest.skip
    def testPartialWriteAtSecondChunkOffset(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 10
                    image.chunks_per_segment = 3
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    image.SeekWrite(10, 0)
                    image.Write(b"ab")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.SeekRead(10, 0)
                    res = image.Read(4)
                    self.assertEqual(b"ab", res)

    #@unittest.skip
    def testPartialSparseWriteInEndSecondChunkToInFarBevvy(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    image.SeekWrite(5, 0)
                    image.Write(b"abcdefabcdefabcdef")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    res = image.ReadAll()
                    self.assertEqual(b"\0\0\0\0\0abcdefabcdefabcdef", res)

    #@unittest.skip
    def testPartialSparseWriteInMidSecondChunkToInFarBevvy(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    image.SeekWrite(4, 0)
                    image.Write(b"abcdefabcdefabcdef")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    res = image.ReadAll()
                    self.assertEqual(b"\0\0\0\0abcdefabcdefabcdef", res)

    #@unittest.skip
    def testPartialSparseWriteInSecondChunkToInFarBevvy(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    image.SeekWrite(3, 0)
                    image.Write(b"abcdefabcdefabcdef")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    res = image.ReadAll()
                    self.assertEqual(b"\0\0\0abcdefabcdefabcdef", res)

    #@unittest.skip
    def testPartialSparseWriteInFirstChunkToInFarBevvy(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    image.SeekWrite(1, 0)
                    image.Write(b"abcdefabcdefabcdef")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    res = image.ReadAll()
                    self.assertEqual(b"\0abcdefabcdefabcdef", res)

    #@unittest.skip
    def testPartialSparseWriteInFirstChunkToInNextBevy(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    image.SeekWrite(1, 0)
                    image.Write(b"abcdef")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    res = image.ReadAll()
                    self.assertEqual(b"\0abcdef", res)

    #@unittest.skip
    def testPartialSparseWriteInFirstChunkToEndOfBevy(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    image.SeekWrite(1, 0)
                    image.Write(b"abcde")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    res = image.ReadAll()
                    self.assertEqual(b"\0abcde", res)

    #@unittest.skip
    def testPartialSparseWriteInFirstChunkToIntoNextChunk(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    image.SeekWrite(1, 0)
                    image.Write(b"abc")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    res = image.ReadAll()
                    self.assertEqual(b"\0abc", res)

    #@unittest.skip
    def testPartialSparseWriteInFirstChunkToEndOfChunk(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    image.SeekWrite(1, 0)
                    image.Write(b"ab")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    res = image.ReadAll()
                    self.assertEqual(b"\0ab", res)

    #@unittest.skip
    def testPartialSparseWriteInFirstChunk(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    image.SeekWrite(1, 0)
                    image.Write(b"a")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    res = image.ReadAll()
                    self.assertEqual(b"\0a", res)


    #@unittest.skip
    def testBevvyPlusOneSizeWrite(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b"abcabca")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    res = image.Read(7)
                    self.assertEqual(b"abcabca", res)

    #@unittest.skip
    def testBevvySizeWrite(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b"abcabc")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    res = image.Read(6)
                    self.assertEqual(b"abcabc", res)

    #@unittest.skip
    def testTwoChunkPlusOneWrite(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 10
                    image.chunks_per_segment = 3
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b"abcdeabcdeabcdeabcdea")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    res = image.Read(21)
                    self.assertEqual(b"abcdeabcdeabcdeabcdea", res)

    #@unittest.skip
    def testTwoChunkWrite(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 10
                    image.chunks_per_segment = 3
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b"abcdeabcdeabcdeabcde")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    res = image.Read(20)
                    self.assertEqual(b"abcdeabcdeabcdeabcde", res)

    #@unittest.skip
    def testSingleChunkPlusOneWrite(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    image.Write(b"abcd")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    res = image.Read(4)
                    self.assertEqual(b"abcd", res)

    #@unittest.skip
    def testSingleChunkWrite(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    image.Write(b"abc")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    res = image.Read(3)
                    self.assertEqual(b"abc", res)


    #@unittest.skip
    def testPartialWriteAtZeroOffset(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_RANDOMSTREAM_TYPE) as image:
                    image.chunk_size = 10
                    image.chunks_per_segment = 3
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    image.Write(b"ab")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    res = image.Read(2)
                    self.assertEqual(b"ab", res)


if __name__ == '__main__':
    #logging.getLogger().setLevel(logging.DEBUG)
    unittest.main()
