from __future__ import unicode_literals
# Copyright 2014 Google Inc. All rights reserved.
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
from pyaff4 import keybag


class AFF4ImageTest(unittest.TestCase):
    filename = "/tmp/aff4_test_encrypted.zip"
    filename_urn = rdfvalue.URN.FromFileName(filename)
    image_name = "image.dd"

    def tearDown(self):
        try:
            #os.unlink(self.filename)
            pass
        except (IOError, OSError):
            pass

    #@unittest.skip
    def testSmallWriteNoEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.KeyBag.create("secret")

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE) as image:
                    image.chunk_size = 5
                    image.chunks_per_segment = 2
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.DEBUG = True
                    image.Write(b"abcd")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.DEBUG = True
                    self.assertEquals(4, image.Size())
                    self.assertEqual(b"abcd", image.ReadAll())

    #@unittest.skip
    def testChunkSizeWriteNoEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.KeyBag.create("secret")

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE) as image:
                    image.chunk_size = 5
                    image.chunks_per_segment = 2
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.DEBUG = True
                    image.Write(b"abcda")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.DEBUG = True
                    self.assertEquals(5, image.Size())
                    self.assertEqual(b"abcda", image.ReadAll())

    #@unittest.skip
    def testChunkSizePlusOneWriteNoEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.KeyBag.create("secret")

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE) as image:
                    image.chunk_size = 5
                    image.chunks_per_segment = 2
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.DEBUG = True
                    image.Write(b"abcdaa")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.DEBUG = True
                    self.assertEquals(6, image.Size())
                    self.assertEqual(b"abcdaa", image.ReadAll())

    #@unittest.skip
    def testBevySizeWriteNoEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.KeyBag.create("secret")

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE) as image:
                    image.chunk_size = 5
                    image.chunks_per_segment = 2
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.DEBUG = True
                    image.Write(b"abcdeabcde")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.DEBUG = True
                    self.assertEquals(10, image.Size())
                    self.assertEqual(b"abcdeabcde", image.ReadAll())

    #@unittest.skip
    def testBevySizePlusOneWriteNoEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.KeyBag.create("secret")

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE) as image:
                    image.chunk_size = 5
                    image.chunks_per_segment = 2
                    image.setKeyBag(kb)
                    image.DEBUG = True
                    image.setKey(kb.unwrap_key("secret"))
                    image.Write(b"abcdeabcdea")


        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                resolver.Set(lexicon.transient_graph, image.urn, lexicon.AFF4_STORED,
                             rdfvalue.URN(zip_file.urn))
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.DEBUG = True
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    self.assertEquals(11, image.Size())
                    self.assertEqual(b"abcdeabcdea", image.ReadAll())

    #@unittest.skip
    def testSmallWriteEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.KeyBag.create("secret")

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE) as image:
                    image.DEBUG = False
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.Write(b"abcd")

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.DEBUG = False
                    self.assertEquals(4, image.Size())
                    self.assertEqual(b"abcd", image.ReadAll())

    #@unittest.skip
    def testChunkSizeWriteEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.KeyBag.create("secret")

        txt = b'a' * 512

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE) as image:
                    image.DEBUG = False
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.Write(txt)

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.DEBUG = False
                    self.assertEquals(512, image.Size())
                    self.assertEqual(txt, image.ReadAll())

    #@unittest.skip
    def testChunkSizePlusOneWriteEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.KeyBag.create("secret")
        txt = b'a' * 512 + b'b'
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE) as image:
                    image.DEBUG = False
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.Write(txt)

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.DEBUG = False
                    self.assertEquals(513, image.Size())
                    self.assertEqual(txt, image.ReadAll())

    #@unittest.skip
    def testBevySizeWriteEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.KeyBag.create("secret")
        txt = b'a' * 512 * 1024
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE) as image:
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.Write(txt)

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.DEBUG = False
                    self.assertEquals(512*1024, image.Size())
                    self.assertEqual(txt, image.ReadAll())

    #@unittest.skip
    def testBevySizePlusOneWriteEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.KeyBag.create("secret")
        txt = b'a' * 512 * 1024 + b'b'
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE) as image:
                    image.DEBUG = False
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.Write(txt)

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.DEBUG = False
                    self.assertEquals(512*1024+1, image.Size())
                    self.assertEqual(txt, image.ReadAll())

if __name__ == '__main__':
    #logging.getLogger().setLevel(logging.DEBUG)
    unittest.main()
