# -*- coding: utf-8 -*-
#
# Copyright 2016-2018 Schatz Forensic Pty Ltd. All rights reserved.
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

from pyaff4 import data_store, container, logical
from pyaff4 import escaping
from pyaff4 import lexicon
from pyaff4 import rdfvalue, linear_hasher, hashes
import unittest
import traceback
import os
import io
import tempfile
import random
import math
import platform




"""
Tests logical file creation
"""
class LogicalTest(unittest.TestCase):
    testImagesPath = os.path.join(os.path.dirname(__file__), u"..", u"test_images", u"AFF4-L")


    def setUp(self):
        pass

    # create a single path image using the Push API (block by block writing)
    def createAndReadSinglePathImagePush(self, containerName, pathName, arnPathFragment, minImageStreamSize):
        try:
            hasher = linear_hasher.PushHasher([lexicon.HASH_SHA1, lexicon.HASH_MD5])

            container_urn = rdfvalue.URN.FromFileName(containerName)
            with data_store.MemoryDataStore() as resolver:
                with container.Container.createURN(resolver, container_urn) as volume:
                    volume.maxSegmentResidentSize = minImageStreamSize
                    with volume.newLogicalStream(pathName, 20) as writer:
                        writer_arn = writer.urn

                        # add in some data using the Push API, hashing while we go
                        data = u"helloworld"
                        data_bytes = data.encode("utf-8")
                        writer.Write(data_bytes)
                        hasher.update(data_bytes)
                        writer.Write(data_bytes)
                        hasher.update(data_bytes)

                        # write in the hashes before auto-close
                        for h in hasher.hashes:
                            hh = hashes.newImmutableHash(h.hexdigest(), hasher.hashToType[h])
                            volume.resolver.Add(volume.urn, writer_arn, rdfvalue.URN(lexicon.standard.hash), hh)



            with container.Container.openURNtoContainer(container_urn) as volume:
                images = list(volume.images())
                self.assertEqual(1, len(images), "Only one logical image")
                self.assertEqual(pathName, images[0].name(), "unicode filename should be preserved")

                fragment = escaping.member_name_for_urn(images[0].urn.value, volume.version, base_urn=volume.urn, use_unicode=True)

                self.assertEqual(arnPathFragment, fragment)
                try:
                    with volume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                        txt = fd.ReadAll()
                        self.assertEqual(b"helloworldhelloworld", txt, "content should be same")
                except Exception:
                    traceback.print_exc()
                    self.fail()
        except Exception:
            traceback.print_exc()
            self.fail()

        finally:
            os.unlink(containerName)

    # create a single path image using the Pull API (Streaming API)
    def createAndReadSinglePathImage(self, containerName, pathName, arnPathFragment):
        try:
            container_urn = rdfvalue.URN.FromFileName(containerName)
            with data_store.MemoryDataStore() as resolver:
                urn = None
                with container.Container.createURN(resolver, container_urn) as volume:
                    src = io.BytesIO("hello".encode('utf-8'))
                    urn = volume.writeLogical(pathName, src, 10)


            with container.Container.openURNtoContainer(container_urn) as volume:
                images = list(volume.images())
                self.assertEqual(1, len(images), "Only one logical image")
                imagename = images[0].name()
                self.assertEqual(pathName, imagename, "unicode filename should be preserved")

                fragment = escaping.member_name_for_urn(images[0].urn.value, volume.version, base_urn=volume.urn, use_unicode=True)

                self.assertEqual(arnPathFragment, fragment)
                try:
                    with volume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                        txt = fd.ReadAll()
                        self.assertEqual(b"hello", txt, "content should be same")
                except Exception:
                    traceback.print_exc()
                    self.fail()
        except Exception:
            traceback.print_exc()
            self.fail()

        finally:
            os.unlink(containerName)

    def testWindowsUNCLogicalImagePushImageStream(self):
        containerName = tempfile.gettempdir() + "/test-imagetream.aff4"
        self.createAndReadSinglePathImageImageStream(containerName, u"\\\\foo\\bar.txt", u"foo/bar.txt")

    def testWindowsUNCLogicalImagePushZipSegment(self):
        containerName = tempfile.gettempdir() + "/test-unc1.aff4"
        self.createAndReadSinglePathImagePush(containerName, u"\\\\foo\\bar.txt", u"foo/bar.txt", 1024)

    def testWindowsUNCLogicalImagePushImageStream(self):
        containerName = tempfile.gettempdir() + "/test-unc2.aff4"
        self.createAndReadSinglePathImagePush(containerName, u"\\\\foo\\bar.txt", u"foo/bar.txt", 2)

    def testWindowsUNCLogicalImage(self):
        containerName = tempfile.gettempdir() + "/test-unc3.aff4"
        self.createAndReadSinglePathImage(containerName, u"\\\\foo\\bar.txt", u"foo/bar.txt")

    def testUnixASCIINoSlashLogicalImage(self):
        containerName = tempfile.gettempdir() + "/test-unix1.aff4"
        self.createAndReadSinglePathImage(containerName, u"foo/bar.txt", u"/foo/bar.txt")

    def testUnixASCIISlashLogicalImage(self):
        containerName = tempfile.gettempdir() + "/test-unix2.aff4"
        self.createAndReadSinglePathImage(containerName, u"/foo/bar.txt", u"/foo/bar.txt")

    def testUnixUnicodeLogicalImage(self):
        containerName = tempfile.gettempdir() + "/test-unicodepath.aff4"
        self.createAndReadSinglePathImage(containerName, u"/犬/ネコ.txt", u"/犬/ネコ.txt")

    def testWindowsDriveLogicalImage(self):
        containerName = tempfile.gettempdir() + "/test-windowsdrive.aff4"
        self.createAndReadSinglePathImage(containerName, u"c:\\犬\\ネコ.txt", u"/c:/犬/ネコ.txt")

    def testZeroLengthLogicalStreamNoWrite(self):
        containerName = tempfile.gettempdir() + "/test-zerolength.aff4"
        try:
            container_urn = rdfvalue.URN.FromFileName(containerName)
            with data_store.MemoryDataStore() as resolver:
                with container.Container.createURN(resolver, container_urn) as volume:
                    with volume.newLogicalStream("foobar", 0) as writer:
                        print()

            with container.Container.openURNtoContainer(container_urn) as volume:
                images = list(volume.images())
                self.assertEqual(1, len(images), "Only one logical image")
                self.assertEqual("foobar", images[0].name(), "information.turtle should be escaped")

                with volume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                    try:
                        txt = fd.ReadAll()
                        self.assertEqual(b"", txt, "escaped file returned")
                        pass
                    except Exception:
                        traceback.print_exc()
                        self.fail("content of information.turtle is wrong")

        except Exception:
            traceback.print_exc()
            self.fail()

        finally:
            os.unlink(containerName)

    def testZeroLengthLogicalStream(self):
        containerName = tempfile.gettempdir() + "/test-zerolength.aff4"
        try:
            container_urn = rdfvalue.URN.FromFileName(containerName)
            with data_store.MemoryDataStore() as resolver:
                with container.Container.createURN(resolver, container_urn) as volume:

                    with volume.newLogicalStream("foobar", 0) as writer:
                        writer.Write(b"")

            with container.Container.openURNtoContainer(container_urn) as volume:
                images = list(volume.images())
                self.assertEqual(1, len(images), "Only one logical image")
                self.assertEqual("foobar", images[0].name(), "information.turtle should be escaped")

                with volume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                    try:
                        txt = fd.ReadAll()
                        self.assertEqual(b"", txt, "escaped file returned")
                        pass
                    except Exception:
                        traceback.print_exc()
                        self.fail("content of information.turtle is wrong")

        except Exception:
            traceback.print_exc()
            self.fail()

        finally:
            os.unlink(containerName)

    def testZeroLengthLogical(self):
        containerName = tempfile.gettempdir() + "/test-zerolength.aff4"
        try:
            container_urn = rdfvalue.URN.FromFileName(containerName)
            with data_store.MemoryDataStore() as resolver:
                with container.Container.createURN(resolver, container_urn) as volume:
                    src = io.BytesIO(u"".encode('utf-8'))
                    volume.writeLogical(u"foobar", src, 0)

            with container.Container.openURNtoContainer(container_urn) as volume:
                images = list(volume.images())
                self.assertEqual(1, len(images), "Only one logical image")
                self.assertEqual("foobar", images[0].name(), "information.turtle should be escaped")

                with volume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                    try:
                        txt = fd.ReadAll()
                        self.assertEqual(b"", txt, "escaped file returned")
                        pass
                    except Exception:
                        traceback.print_exc()
                        self.fail("content of information.turtle is wrong")

        except Exception:
            traceback.print_exc()
            self.fail()

        finally:
            os.unlink(containerName)

    def testAFF4ReservedSegmentCollision(self):
        containerName = tempfile.gettempdir() + "/test.aff4"
        try:
            container_urn = rdfvalue.URN.FromFileName(containerName)
            with data_store.MemoryDataStore() as resolver:
                with container.Container.createURN(resolver, container_urn) as volume:
                    src = io.BytesIO(u"hello".encode('utf-8'))
                    volume.writeLogical(u"information.turtle", src, 10)

            with container.Container.openURNtoContainer(container_urn) as volume:
                images = list(volume.images())
                self.assertEqual(1, len(images), "Only one logical image")
                self.assertEqual("information.turtle", images[0].name(), "information.turtle should be escaped")

                with volume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                    try:
                        txt = fd.ReadAll()
                        self.assertEqual(b"hello", txt, "escaped file returned")
                        pass
                    except Exception:
                        traceback.print_exc()
                        self.fail("content of information.turtle is wrong")

        except Exception:
            traceback.print_exc()
            self.fail()

        finally:
            os.unlink(containerName)

    def onValidHash(self, typ, hash, imageStreamURI):
        self.assertEqual(True,True)

    def onInvalidHash(self, typ, hasha, hashb, streamURI):
        self.fail()

    @unittest.skipIf(platform.system() == "Windows", "Only works on unix")
    def testFuzz(self):
        chunksize=512
        for length in [chunksize-1, chunksize, chunksize+1, chunksize*2-1, chunksize*2, chunksize*2+1, chunksize*1000, 0]:
            for maxSegmentResidentSize in [0, 1, chunksize-1, chunksize, chunksize+1]:
                try:
                    containerName = tempfile.gettempdir() + "/testfuzz-length-%d-maxresident%d.aff4" % (length, maxSegmentResidentSize)
                    print(containerName)
                    hasher = linear_hasher.PushHasher([lexicon.HASH_SHA1, lexicon.HASH_MD5])

                    container_urn = rdfvalue.URN.FromFileName(containerName)
                    with data_store.MemoryDataStore() as resolver:
                        with container.Container.createURN(resolver, container_urn) as volume:
                            volume.maxSegmentResidentSize = maxSegmentResidentSize
                            with volume.newLogicalStream("/foo", length) as writer:
                                with open("/dev/random", "rb") as randomStream:
                                    writer.chunk_size = chunksize
                                    writer_arn = writer.urn

                                    pos = 0
                                    while pos < length:
                                        toread = int(min(math.ceil(1024 * random.random()), length - pos))
                                        data = randomStream.read(toread)
                                        writer.Write(data)
                                        hasher.update(data)
                                        pos += toread

                            # write in the hashes before auto-close
                            for h in hasher.hashes:
                                hh = hashes.newImmutableHash(h.hexdigest(), hasher.hashToType[h])
                                volume.resolver.Add(volume.urn, writer_arn, rdfvalue.URN(lexicon.standard.hash), hh)
                            print()

                    with container.Container.openURNtoContainer(container_urn) as volume:
                        images = list(volume.images())
                        self.assertEqual(1, len(images), "Only one logical image")
                        self.assertEqual("/foo", images[0].name(), "unicode filename should be preserved")

                        fragment = escaping.member_name_for_urn(images[0].urn.value, volume.version,
                                                                base_urn=volume.urn, use_unicode=True)

                        hasher = linear_hasher.LinearHasher2(volume.resolver, self)
                        for image in volume.images():
                            hasher.hash(image)

                    os.unlink(containerName)
                except Exception:
                    traceback.print_exc()
                    self.fail()
                    continue


if __name__ == '__main__':
    unittest.main()