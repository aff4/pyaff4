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
from pyaff4 import keybag


class AFF4EncryptedStreamTest(unittest.TestCase):
    filename = tempfile.gettempdir() + u"/aff4_encryptedstream_test.zip"
    filename_urn = rdfvalue.URN.FromFileName(filename)
    image_name = "image.dd"

    def setUp(self):
        try:
            os.unlink(self.filename)
            pass
        except (IOError, OSError):
            pass

    def tearDown(self):
        try:
            os.unlink(self.filename)
            pass
        except (IOError, OSError):
            pass

    #@unittest.skip
    def testSmallWriteNoEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.PasswordWrappedKeyBag.create("secret")

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
                    image.Write(b"abcd")
                    self.assertEquals(b"abcd", image.Read(4))
                    image.SeekRead(0,0)
                    self.assertEquals(b"abcd", image.Read(5))

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.setKeyBag(kb)
                    image.DEBUG = True
                    image.setKey(kb.unwrap_key("secret"))
                    self.assertEquals(4, image.Size())
                    self.assertEqual(b"abcd", image.ReadAll())

    #@unittest.skip
    def testChunkSizeWriteNoEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.PasswordWrappedKeyBag.create("secret")

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
                    image.Write(b"abcda")
                    self.assertEquals(b"abcda", image.Read(5))

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.setKeyBag(kb)
                    image.DEBUG = True
                    image.setKey(kb.unwrap_key("secret"))
                    self.assertEquals(5, image.Size())
                    self.assertEqual(b"abcda", image.ReadAll())

    #@unittest.skip
    def testChunkSizePlusOneWriteNoEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.PasswordWrappedKeyBag.create("secret")

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
                    image.Write(b"abcdaa")
                    self.assertEquals(b"abcdaa", image.Read(6))

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.setKeyBag(kb)
                    image.DEBUG = True
                    image.setKey(kb.unwrap_key("secret"))
                    self.assertEquals(6, image.Size())
                    self.assertEqual(b"abcdaa", image.ReadAll())

    #@unittest.skip
    def testBevySizeWriteNoEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.PasswordWrappedKeyBag.create("secret")

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
                    image.Write(b"abcdeabcde")
                    image.SeekRead(5,0)
                    self.assertEqual(b"abcde", image.Read(5))

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.setKeyBag(kb)
                    image.DEBUG = True
                    image.setKey(kb.unwrap_key("secret"))
                    self.assertEquals(10, image.Size())
                    self.assertEqual(b"abcdeabcde", image.ReadAll())

    #@unittest.skip
    def testBevySizePlusOneWriteNoEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.PasswordWrappedKeyBag.create("secret")

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
                    image.SeekRead(5, 0)
                    self.assertEqual(b"abcdea", image.Read(6))


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

        kb = keybag.PasswordWrappedKeyBag.create("secret")

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
                    image.DEBUG = False
                    image.setKey(kb.unwrap_key("secret"))
                    self.assertEquals(4, image.Size())
                    self.assertEqual(b"abcd", image.ReadAll())

    #@unittest.skip
    def testChunkSizeWriteEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.PasswordWrappedKeyBag.create("secret")

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
                    image.DEBUG = False
                    image.setKey(kb.unwrap_key("secret"))
                    self.assertEquals(512, image.Size())
                    self.assertEqual(txt, image.ReadAll())

    #@unittest.skip
    def testChunkSizePlusOneWriteEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.PasswordWrappedKeyBag.create("secret")
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
                    image.DEBUG = False
                    image.setKey(kb.unwrap_key("secret"))
                    self.assertEquals(513, image.Size())
                    self.assertEqual(txt, image.ReadAll())

    #@unittest.skip
    def testBevySizeWriteEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.PasswordWrappedKeyBag.create("secret")
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
                    image.DEBUG = False
                    image.setKey(kb.unwrap_key("secret"))
                    self.assertEquals(512*1024, image.Size())
                    self.assertEqual(txt, image.ReadAll())

    #@unittest.skip
    def testBevySizePlusOneWriteEncryption(self):
        version = container.Version(0, 1, "pyaff4")

        kb = keybag.PasswordWrappedKeyBag.create("secret")
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
                    image.DEBUG = False
                    image.setKey(kb.unwrap_key("secret"))
                    self.assertEquals(512*1024+1, image.Size())
                    self.assertEqual(txt, image.ReadAll())

    #@unittest.skip
    def testAppendOfEncryptedOutOfOrder(self):
        version = container.Version(0, 1, "pyaff4")
        print(self.filename)
        kb = keybag.PasswordWrappedKeyBag.create("secret")
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE) as image:
                    image.DEBUG = True
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.SeekWrite(512 * 1024 +2, 0)
                    image.Write(b'b' * 512)

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("random"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE) as image:
                    image.DEBUG = True
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.SeekWrite(0, 0)
                    image.Write(b'b')

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.setKeyBag(kb)
                    image.DEBUG = True
                    image.setKey(kb.unwrap_key("secret"))
                    self.assertEquals(1024*512+2+512, image.Size())
                    all = image.ReadAll()
                    expected = b'b' + (b'\0'*((512*1024)-1)) + (b'\0'*2) + (b'b'* 512)
                    self.assertEquals(expected , all)


    #@unittest.skip
    def testAppendOfEncryptedSingleChunkPlusOne(self):
        version = container.Version(0, 1, "pyaff4")
        print(self.filename)
        kb = keybag.PasswordWrappedKeyBag.create("secret")
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
                    image.DEBUG = True
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.Write(b'a' * 512)

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("random"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE) as image:
                    image.DEBUG = True
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.SeekWrite(512, 0)
                    image.Write(b'b')

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.setKeyBag(kb)
                    image.DEBUG = True
                    image.setKey(kb.unwrap_key("secret"))
                    self.assertEquals(513, image.Size())
                    self.assertEquals(b'a'*512 + b'b', image.ReadAll())

    #@unittest.skip
    def testAppendOfEncryptedSingleChunk(self):
        version = container.Version(0, 1, "pyaff4")
        print(self.filename)
        kb = keybag.PasswordWrappedKeyBag.create("secret")
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
                    image.DEBUG = True
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.Write(b'a' * 512)

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("random"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE) as image:
                    image.DEBUG = True
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.Write(b'b')

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.setKeyBag(kb)
                    image.DEBUG = True
                    image.setKey(kb.unwrap_key("secret"))
                    self.assertEquals(512, image.Size())
                    self.assertEquals(b'b' + b'a'*511, image.ReadAll())

    #@unittest.skip
    def testAppendOfEncryptedSubChunk(self):
        version = container.Version(0, 1, "pyaff4")
        print(self.filename)
        kb = keybag.PasswordWrappedKeyBag.create("secret")
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
                    image.DEBUG = True
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.Write(b'a' * 2)

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("random"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(
                    resolver, self.image_urn_2, self.volume_urn, type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE) as image:
                    image.DEBUG = True
                    image.setKeyBag(kb)
                    image.setKey(kb.unwrap_key("secret"))
                    image.Write(b'b')

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    image.setKeyBag(kb)
                    image.DEBUG = True
                    image.setKey(kb.unwrap_key("secret"))
                    self.assertEquals(2, image.Size())
                    self.assertEquals(b'ba', image.ReadAll())

if __name__ == '__main__':
    #logging.getLogger().setLevel(logging.DEBUG)
    unittest.main()
