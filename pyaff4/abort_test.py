# Copyright 2019 Schatz Forensic Pty Ltd All rights reserved.
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

from future import standard_library

standard_library.install_aliases()
from builtins import range
import os
import unittest
import traceback
import tempfile

from pyaff4 import aff4_image
from pyaff4 import zip
from pyaff4 import data_store, container, hexdump
from pyaff4 import escaping
from pyaff4 import lexicon
from pyaff4 import rdfvalue, linear_hasher, hashes



class AFF4AbortImageStreamTest(unittest.TestCase):
    filename = tempfile.gettempdir()  + u"/aff4_test_abort.zip"
    filename_urn = rdfvalue.URN.FromFileName(filename)
    image_name = "image.dd"

    def tearDown(self):
        try:
            os.unlink(self.filename)
            pass
        except (IOError, OSError):
            pass

    #@unittest.skip
    def testAbortEncryptedImageStreamMultiBevy(self):
        version = container.Version(1, 1, "pyaff4")
        lex = lexicon.standard11

        try:
            os.unlink(self.filename)
        except (IOError, OSError):
            pass

        container_urn = rdfvalue.URN.FromFileName(self.filename)
        with data_store.MemoryDataStore() as resolver:
            with container.Container.createURN(resolver, container_urn, encryption=True) as volume:
                volume.block_store_stream.chunks_per_segment = 1
                #volume.block_store_stream.DEBUG = True
                volume.setPassword("password")
                logicalContainer = volume.getChildContainer()
                logicalContainer.maxSegmentResidentSize = 512
                with logicalContainer.newLogicalStream("hello", 1024) as w:
                    w.chunks_per_segment = 1
                    w.chunk_size = 512
                    w.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    w.Write(b'a' * 512)
                    w.Write(b'b' * 512)
                    w.Abort()

                with logicalContainer.newLogicalStream("foo", 1024) as w:
                    w.chunks_per_segment = 1
                    w.chunk_size = 512
                    w.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    w.Write(b'd' * 512)
                    w.Write(b'e' * 512)

        container_urn = rdfvalue.URN.FromFileName(self.filename)
        with container.Container.openURNtoContainer(container_urn, mode="+") as volume:
            #volume.block_store_stream.DEBUG = True
            volume.setPassword("password")

            childVolume = volume.getChildContainer()
            images = list(childVolume.images())
            self.assertEquals(1, len(images))
            with childVolume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                self.assertEqual(b'd' * 512, fd.Read(512))
                self.assertEqual(b'e' * 512, fd.Read(512))

    #@unittest.skip
    def testAbortEncryptedImageStreamSingleBevy(self):
        version = container.Version(1, 1, "pyaff4")
        lex = lexicon.standard11

        try:
            os.unlink(self.filename)
        except (IOError, OSError):
            pass

        container_urn = rdfvalue.URN.FromFileName(self.filename)
        with data_store.MemoryDataStore() as resolver:
            with container.Container.createURN(resolver, container_urn, encryption=True) as volume:
                volume.block_store_stream.chunks_per_segment = 1
                volume.block_store_stream.DEBUG = True
                volume.setPassword("password")
                logicalContainer = volume.getChildContainer()
                logicalContainer.maxSegmentResidentSize = 512
                with logicalContainer.newLogicalStream("hello", 1024) as w:
                    w.chunks_per_segment = 2
                    w.chunk_size = 512
                    w.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    w.Write(b'a' * 512)
                    w.Write(b'b' * 512)
                    w.Abort()

                with logicalContainer.newLogicalStream("foo", 1024) as w:
                    w.chunks_per_segment = 2
                    w.chunk_size = 512
                    w.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    w.Write(b'd' * 512)
                    w.Write(b'e' * 512)

        container_urn = rdfvalue.URN.FromFileName(self.filename)
        with container.Container.openURNtoContainer(container_urn, mode="+") as volume:
            volume.block_store_stream.DEBUG = True
            volume.setPassword("password")

            childVolume = volume.getChildContainer()
            images = list(childVolume.images())
            self.assertEquals(1, len(images))
            with childVolume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                self.assertEqual(b'd' * 512, fd.Read(512))
                self.assertEqual(b'e' * 512, fd.Read(512))


    #@unittest.skip
    def testAbortEncryptedZipStream(self):
        version = container.Version(1, 1, "pyaff4")
        lex = lexicon.standard11

        try:
            os.unlink(self.filename)
        except (IOError, OSError):
            pass

        container_urn = rdfvalue.URN.FromFileName(self.filename)
        with data_store.MemoryDataStore() as resolver:
            with container.Container.createURN(resolver, container_urn, encryption=True) as volume:
                volume.block_store_stream.chunks_per_segment = 1
                volume.block_store_stream.DEBUG = True
                volume.setPassword("password")
                logicalContainer = volume.getChildContainer()
                logicalContainer.maxSegmentResidentSize = 2048
                with logicalContainer.newLogicalStream("hello", 1024) as w:
                    w.chunks_per_segment = 1
                    w.chunk_size = 512
                    w.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    w.Write(b'a' * 512)
                    w.Write(b'b' * 512)
                    w.Abort()

                with logicalContainer.newLogicalStream("foo", 1024) as w:
                    w.chunks_per_segment = 1
                    w.chunk_size = 512
                    w.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    w.Write(b'd' * 512)
                    w.Write(b'e' * 512)

        container_urn = rdfvalue.URN.FromFileName(self.filename)
        with container.Container.openURNtoContainer(container_urn, mode="+") as volume:
            volume.block_store_stream.DEBUG = True
            volume.setPassword("password")

            childVolume = volume.getChildContainer()
            images = list(childVolume.images())
            self.assertEquals(1, len(images))
            with childVolume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                self.assertEqual(b'd' * 512, fd.Read(512))
                self.assertEqual(b'e' * 512, fd.Read(512))

    #@unittest.skip
    def testAbortEncrypted(self):
        version = container.Version(1, 1, "pyaff4")
        lex = lexicon.standard11

        try:
            os.unlink(self.filename)
        except (IOError, OSError):
            pass

        container_urn = rdfvalue.URN.FromFileName(self.filename)
        with data_store.MemoryDataStore() as resolver:
            with container.Container.createURN(resolver, container_urn, encryption=True) as volume:
                #volume.block_store_stream.chunks_per_segment = 1
                volume.setPassword("password")
                logicalContainer = volume.getChildContainer()
                logicalContainer.maxSegmentResidentSize = 512
                with logicalContainer.newLogicalStream("hello", 1024) as w:
                    w.chunks_per_segment = 1
                    w.chunk_size = 512
                    w.Write(b'a' * 512)
                    w.Write(b'b' * 512)
                    w.SeekWrite(0,0)
                    w.Write(b'c' * 512)
                    w.Abort()

        container_urn = rdfvalue.URN.FromFileName(self.filename)
        with container.Container.openURNtoContainer(container_urn) as volume:
                volume.setPassword("password")
                childVolume = volume.getChildContainer()
                images = list(childVolume.images())
                self.assertEquals(0, len(images))



    #@unittest.skip
    def testAbortImageStreamWithMultipleBevys(self):
        version = container.Version(0, 1, "pyaff4")

        image_urn_2 = None

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                image_urn = self.volume_urn.Append(self.image_name)

                image_urn_2 = image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, image_urn_2, self.volume_urn) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b"abcdefgabcdefgabcdefgabcdefg")

                    image.Abort()


        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:

                for i in range(0,1):
                    seg_arn = image_urn_2.Append("%08d" % i)
                    idx_arn = image_urn_2.Append("%08d.index" % i)
                    self.assertFalse(zip_file.ContainsMember(seg_arn))
                    self.assertFalse(zip_file.ContainsMember(idx_arn))

        self.assertEquals(518, os.stat(self.filename).st_size)

    #@unittest.skip
    def testAbortImageStreamWithSingleBevyThenSecondStream(self):
        version = container.Version(0, 1, "pyaff4")

        image_urn_3 = None

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                image_urn = self.volume_urn.Append(self.image_name)

                image_urn_2 = image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, image_urn_2, self.volume_urn) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    image.Write(b"abcdefg")
                    image.Abort()

                self.image_urn_3 = image_urn.Append("3")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_3, self.volume_urn) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    image.Write(b"abcdefg")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                for i in range(0,2):
                    seg_arn = image_urn_2.Append("%08d" % i)
                    idx_arn = image_urn_2.Append("%08d.index" % i)
                    self.assertFalse(zip_file.ContainsMember(seg_arn))
                    self.assertFalse(zip_file.ContainsMember(idx_arn))

                for i in range(0,2):
                    seg_arn = self.image_urn_3.Append("%08d" % i)
                    idx_arn = self.image_urn_3.Append("%08d.index" % i)
                    self.assertTrue(zip_file.ContainsMember(seg_arn))
                    self.assertTrue(zip_file.ContainsMember(idx_arn))

            with resolver.AFF4FactoryOpen(self.image_urn_3) as image:
                image.SeekRead(0, 0)
                res = image.Read(7)
                self.assertEqual(b"abcdefg", res)
        self.assertEquals(1265, os.stat(self.filename).st_size)

    #@unittest.skip
    def testAbortImageStreamWithSingleBevy(self):
        version = container.Version(0, 1, "pyaff4")

        image_urn_2 = None

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                image_urn = self.volume_urn.Append(self.image_name)

                image_urn_2 = image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, image_urn_2, self.volume_urn) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b"abcdefg")

                    image.Abort()


        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:

                for i in range(0,1):
                    seg_arn = image_urn_2.Append("%08d" % i)
                    idx_arn = image_urn_2.Append("%08d.index" % i)
                    self.assertFalse(zip_file.ContainsMember(seg_arn))
                    self.assertFalse(zip_file.ContainsMember(idx_arn))

        self.assertEquals(518, os.stat(self.filename).st_size)

    #@unittest.skip
    def testAbortImageStreamWithSubBevyWrite(self):
        version = container.Version(0, 1, "pyaff4")

        image_urn_2 = None

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                image_urn = self.volume_urn.Append(self.image_name)

                image_urn_2 = image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, image_urn_2, self.volume_urn) as image:
                    image.chunk_size = 3
                    image.chunks_per_segment = 2
                    image.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)

                    image.Write(b"abcde")

                    image.Abort()


        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:

                for i in range(0,1):
                    seg_arn = image_urn_2.Append("%08d" % i)
                    idx_arn = image_urn_2.Append("%08d.index" % i)
                    self.assertFalse(zip_file.ContainsMember(seg_arn))
                    self.assertFalse(zip_file.ContainsMember(idx_arn))

        self.assertEquals(518, os.stat(self.filename).st_size)

    #@unittest.skip
    def testCreateAndReadSingleImageStreamLogicalPush(self):
        try:
            container_urn = rdfvalue.URN.FromFileName(self.filename)
            with data_store.MemoryDataStore() as resolver:
                with container.Container.createURN(resolver, container_urn) as volume:
                    volume.maxSegmentResidentSize = 4
                    with volume.newLogicalStream("foo", 20) as writer:
                        writer_arn = writer.urn

                        # add in some data using the Push API, hashing while we go
                        data = u"helloworld"
                        data_bytes = data.encode("utf-8")
                        writer.Write(data_bytes)
                        writer.Write(data_bytes)
                        writer.Abort()

            with container.Container.openURNtoContainer(container_urn) as volume:
                images = list(volume.images())
                self.assertEqual(0, len(images), "No logical images")

        except Exception:
            traceback.print_exc()
            self.fail()

    #@unittest.skip
    def testCreateAndReadSingleZipSegmentLogicalPush(self):
        try:
            container_urn = rdfvalue.URN.FromFileName(self.filename)
            with data_store.MemoryDataStore() as resolver:
                with container.Container.createURN(resolver, container_urn) as volume:
                    volume.maxSegmentResidentSize = 40
                    with volume.newLogicalStream("foo", 20) as writer:
                        writer_arn = writer.urn

                        # add in some data using the Push API, hashing while we go
                        data = u"helloworld"
                        data_bytes = data.encode("utf-8")
                        writer.Write(data_bytes)
                        writer.Write(data_bytes)
                        writer.Abort()

            with container.Container.openURNtoContainer(container_urn) as volume:
                images = list(volume.images())
                self.assertEqual(0, len(images), "No logical images")

        except Exception:
            traceback.print_exc()
            self.fail()