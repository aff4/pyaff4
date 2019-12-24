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

from __future__ import unicode_literals
import tempfile

from future import standard_library
standard_library.install_aliases()
from builtins import range
import os
import io
import unittest

from pyaff4 import aff4_image
from pyaff4 import data_store
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import zip
from pyaff4 import container
from pyaff4 import keybag, lexicon, hexdump

src = "I am happy to join with you today in what will go down in history as the greatest demonstration for freedom in the history of our nation.".encode()


class AFF4ImageTest(unittest.TestCase):
    filenameA = tempfile.gettempdir() + "/aff4_cryptimage_test.aff4"
    filenameA_urn = rdfvalue.URN.FromFileName(filenameA)
    image_name = "image.dd"

    filenameB = tempfile.gettempdir() + "/aff4_testB.aff4"

    referenceImagesPath = os.path.join(os.path.dirname(__file__), u"..",
                                       u"test_images")
    cert = os.path.join(referenceImagesPath, u"keys", u"certificate.pem")
    privateKey = os.path.join(referenceImagesPath, u"keys", u"key.pem")

    def setUp(self):
        try:
            os.unlink(self.filenameA)
        except (IOError, OSError):
            pass
        try:
            os.unlink(self.filenameB)
        except (IOError, OSError):
            pass

    def remove(self):
        try:
            os.unlink(self.filenameA)
        except (IOError, OSError):
            pass
        try:
            os.unlink(self.filenameB)
        except (IOError, OSError):
            pass

    def create(self):
        version = container.Version(1, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filenameA_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filenameA_urn) as zip_file:
                self.volume_urn = zip_file.urn
                image_urn = self.volume_urn.Append(self.image_name)

                self.crypto_stream_arn = image_urn

                # Use default compression.
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, image_urn, self.volume_urn, type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE) as image:
                    image.chunk_size = 512
                    image.chunks_per_segment = 1024

                    kb = keybag.KeyBag.create("password")
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("password"))

                    for i in range(100):
                        image.Write(src)

                    self.image_urn = image.urn

    @unittest.skip
    def testCreateRegContainer(self):
        try:
            os.unlink(self.filenameB)
        except (IOError, OSError):
            pass

        container_urn = rdfvalue.URN.FromFileName(self.filenameB)
        with data_store.MemoryDataStore() as resolver:

            with container.Container.createURN(resolver, container_urn, encryption=False) as volume:
                #volume.setPassword("password")
                pass

    def testCreateAndReadContainerWithCertEncrypted(self):
        version = container.Version(1, 1, "pyaff4")
        lex = lexicon.standard11

        try:
            os.unlink(self.filenameB)
        except (IOError, OSError):
            pass

        container_urn = rdfvalue.URN.FromFileName(self.filenameB)
        with data_store.MemoryDataStore() as resolver:
            with container.Container.createURN(resolver, container_urn, encryption=True) as volume:
                volume.setPassword("password")
                volume.setPublicKeyCert(self.cert)
                logicalContainer = volume.getChildContainer()
                with logicalContainer.newLogicalStream("hello", 137) as w:
                    w.SeekWrite(2*512,0)
                    w.Write(b'c')

        container_urn = rdfvalue.URN.FromFileName(self.filenameB)
        with container.Container.openURNtoContainer(container_urn) as volume:
                volume.setPrivateKey(self.privateKey)
                childVolume = volume.getChildContainer()
                images = list(childVolume.images())
                with childVolume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                    w.SeekWrite(0, 0)
                    w.Write(b'a' * 512)
                    w.Write(b'b')

        container_urn = rdfvalue.URN.FromFileName(self.filenameB)
        with container.Container.openURNtoContainer(container_urn) as volume:
                volume.setPrivateKey(self.privateKey)
                childVolume = volume.getChildContainer()
                images = list(childVolume.images())
                with childVolume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                    w.SeekWrite(512, 0)
                    w.Write(b'b' * 512)

        container_urn = rdfvalue.URN.FromFileName(self.filenameB)
        with container.Container.openURNtoContainer(container_urn) as volume:
                volume.setPrivateKey(self.privateKey)
                childVolume = volume.getChildContainer()
                images = list(childVolume.images())
                with childVolume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                    self.assertEqual(b'a' * 512, fd.Read(512))
                    self.assertEqual(b'b' * 512, fd.Read(512))
                    self.assertEqual(b'c', fd.Read(512))

    def testCreateAndReadContainerWithCertEncrypted(self):
        version = container.Version(1, 1, "pyaff4")
        lex = lexicon.standard11

        try:
            os.unlink(self.filenameB)
        except (IOError, OSError):
            pass

        container_urn = rdfvalue.URN.FromFileName(self.filenameB)
        with data_store.MemoryDataStore() as resolver:
            with container.Container.createURN(resolver, container_urn, encryption=True) as volume:
                volume.setPassword("password")
                volume.setPublicKeyCert(self.cert)
                logicalContainer = volume.getChildContainer()
                with logicalContainer.newLogicalStream("hello", 137) as w:
                    w.Write(b'a' * 512)
                    w.Write(b'b' * 512)
                    w.SeekWrite(0,0)
                    w.Write(b'c' * 512)

        container_urn = rdfvalue.URN.FromFileName(self.filenameB)
        with container.Container.openURNtoContainer(container_urn) as volume:
                volume.setPrivateKey(self.privateKey)
                childVolume = volume.getChildContainer()
                images = list(childVolume.images())
                with childVolume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                    self.assertEqual(b'c' * 512, fd.Read(512))
                    self.assertEqual(b'b' * 512, fd.Read(512))

    # test that we cant write to an encrypted container that hasnt been opened for append
    def testCreateAndReadContainerAppendFails(self):
        version = container.Version(1, 1, "pyaff4")
        lex = lexicon.standard11

        try:
            os.unlink(self.filenameB)
        except (IOError, OSError):
            pass

        container_urn = rdfvalue.URN.FromFileName(self.filenameB)
        with data_store.MemoryDataStore() as resolver:
            with container.Container.createURN(resolver, container_urn, encryption=True) as volume:
                volume.setPassword("password")
                logicalContainer = volume.getChildContainer()
                with logicalContainer.newLogicalStream("hello", 137) as w:
                    w.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    w.SeekWrite(512*1024, 0)
                    w.Write(b'b' * 512*1024)
                    w.Write(b'c' * 512)

        with data_store.MemoryDataStore() as resolver:
            container_urn = rdfvalue.URN.FromFileName(self.filenameB)
            with container.Container.openURNtoContainer(container_urn) as volume:
                volume.setPassword("password")
                childVolume = volume.getChildContainer()
                images = list(childVolume.images())
                try:
                    with childVolume.resolver.AFF4FactoryOpen(images[0].urn) as w:
                        w.SeekWrite(0,0)
                        w.Write(b'c' * 512)
                    self.fail("Wrote to container")
                except:
                    pass
        print()


    def testCreateAndReadContainerAppendTiny(self):
        version = container.Version(1, 1, "pyaff4")
        lex = lexicon.standard11

        try:
            os.unlink(self.filenameB)
        except (IOError, OSError):
            pass

        container_urn = rdfvalue.URN.FromFileName(self.filenameB)
        with data_store.MemoryDataStore() as resolver:
            with container.Container.createURN(resolver, container_urn, encryption=True) as volume:
                volume.block_store_stream.DEBUG = True
                volume.chunk_size = 5
                volume.chunks_per_segment = 2
                volume.setPassword("password")
                logicalContainer = volume.getChildContainer()
                with logicalContainer.newLogicalStream("hello", 137) as w:
                    w.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_STORED)
                    w.SeekWrite(10, 0)
                    #hexdump.hexdump(w.fd.getvalue())
                    w.Write(b'b' * 10)
                    #hexdump.hexdump(w.fd.getvalue())
                    w.Write(b'c' * 5)


        with data_store.MemoryDataStore() as resolver:
            container_urn = rdfvalue.URN.FromFileName(self.filenameB)
            with container.Container.openURNtoContainer(container_urn, mode="+") as volume:
                volume.block_store_stream.DEBUG = True
                volume.chunk_size = 5
                volume.chunks_per_segment = 2
                volume.setPassword("password")
                childVolume = volume.getChildContainer()
                images = list(childVolume.images())
                with childVolume.resolver.AFF4FactoryOpen(images[0].urn) as w:
                    w.SeekWrite(0,0)
                    w.Write(b'c' * 5)

        container_urn = rdfvalue.URN.FromFileName(self.filenameB)
        with container.Container.openURNtoContainer(container_urn) as volume:
                volume.block_store_stream.DEBUG = True
                volume.setPassword("password")
                childVolume = volume.getChildContainer()
                images = list(childVolume.images())
                with childVolume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                    expected = b'c' * 5 + b'\0' * 5 + b'b' * 10 + b'c' * 5
                    self.assertEqual(expected, fd.ReadAll())

    def testCreateAndReadContainerBadPassword(self):
        version = container.Version(1, 1, "pyaff4")
        lex = lexicon.standard11
        try:
            os.unlink(self.filenameB)
        except (IOError, OSError):
            pass

        container_urn = rdfvalue.URN.FromFileName(self.filenameB)
        with data_store.MemoryDataStore() as resolver:
            with container.Container.createURN(resolver, container_urn, encryption=True) as volume:
                volume.setPassword("password")
                logicalContainer = volume.getChildContainer()
                with logicalContainer.newLogicalStream("hello", 137) as w:
                    w.Write(src)

        container_urn = rdfvalue.URN.FromFileName(self.filenameB)
        with container.Container.openURNtoContainer(container_urn) as volume:
            try:
                volume.setPassword("passwor")
                self.fail("Bad password should throw")
            except:
                pass

    #@unittest.skip
    def testBadAPIUsage(self):
        version = container.Version(1, 1, "pyaff4")
        lex = lexicon.standard11
        try:
            os.unlink(self.filenameB)
        except (IOError, OSError):
            pass

        container_urn = rdfvalue.URN.FromFileName(self.filenameB)
        with data_store.MemoryDataStore() as resolver:
            with container.Container.createURN(resolver, container_urn, encryption=True) as volume:
                try:
                    volume.setPassword("password")
                    volume.block_store_stream.DEBUG = True
                    logicalContainer = volume.getChildContainer()
                    self.fail("Set DEBUG after init() should fail")
                except:
                    pass


    #@unittest.skip
    def testCreateAndReadContainer(self):
        version = container.Version(1, 1, "pyaff4")
        lex = lexicon.standard11
        try:
            os.unlink(self.filenameB)
        except (IOError, OSError):
            pass

        container_urn = rdfvalue.URN.FromFileName(self.filenameB)
        with data_store.MemoryDataStore() as resolver:
            with container.Container.createURN(resolver, container_urn, encryption=True) as volume:
                volume.setPassword("password")
                logicalContainer = volume.getChildContainer()
                with logicalContainer.newLogicalStream("hello", 137) as w:
                    w.Write(src)

        container_urn = rdfvalue.URN.FromFileName(self.filenameB)
        with container.Container.openURNtoContainer(container_urn) as volume:
                volume.setPassword("password")
                childVolume = volume.getChildContainer()
                images = list(childVolume.images())
                with childVolume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                    txt = fd.ReadAll()
                    self.assertEqual(src, txt)

    @unittest.skip
    def testCreateThenRead(self):
        self.create()
        self.read()
        self.remove()

    def read(self):
        resolver = data_store.MemoryDataStore()
        version = container.Version(1, 1, "pyaff4")
        lex = lexicon.standard11

        # This is required in order to load and parse metadata from this volume
        # into a fresh empty resolver.
        with zip.ZipFile.NewZipFile(resolver, version, self.filenameA_urn) as zip_file:
            image_urn = zip_file.urn.Append(self.image_name)

            volume_urn = zip_file.urn

            with resolver.AFF4FactoryOpen(image_urn) as image:
                self.assertEquals(image.chunk_size, 512)
                self.assertEquals(image.chunks_per_segment, 1024)

                kbARN = resolver.GetUnique(volume_urn, image.urn, lex.keyBag)
                kb = keybag.KeyBag.loadFromResolver(resolver, zip_file.urn, kbARN)
                image.setKeyBag(kb)
                image.setKey(kb.unwrap_key("password"))

                self.assertEquals(src, image.Read(len(src)))

                image.SeekRead(137)
                self.assertEquals(src, image.Read(len(src)))

                # read from chunk 2
                image.SeekRead(548)
                self.assertEquals(src, image.Read(len(src)))

                self.assertEquals(len(src)*100, image.Size())




if __name__ == '__main__':
    logging.getLogger().setLevel(logging.DEBUG)
    unittest.main()
