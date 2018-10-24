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
import unittest, traceback
import os, io

"""
Tests logical file creation
"""
class LogicalTest(unittest.TestCase):
    testImagesPath = os.path.join(os.path.dirname(__file__), u"..", u"test_images", u"AFF4-L")


    def setUp(self):
        pass

    # create a single path image using the Push API (block by block writing)
    def createAndReadSinglePathImagePush(self, containerName, pathName, arnPathFragment):
        try:
            hasher = linear_hasher.PushHasher([lexicon.HASH_SHA1, lexicon.HASH_MD5])

            container_urn = rdfvalue.URN.FromFileName(containerName)
            with data_store.MemoryDataStore() as resolver:
                with container.Container.createURN(resolver, container_urn) as volume:
                    with volume.newLogicalStream(pathName, 20) as writer:
                        writer_arn = writer.urn

                        # add in some data using the Push API, hashing while we go
                        data = "helloworld"
                        writer.Write(data)
                        hasher.update(data)
                        writer.Write(data)
                        hasher.update(data)

                        # write in the hashes before auto-close
                        for h in hasher.hashes:
                            hh = hashes.newImmutableHash(h.hexdigest(), hasher.hashToType[h])
                            volume.resolver.Add(writer_arn, rdfvalue.URN(lexicon.standard.hash), hh)



            with container.Container.openURNtoContainer(container_urn) as volume:
                images = list(volume.images())
                self.assertEqual(1, len(images), "Only one logical image")
                self.assertEqual(pathName, images[0].name(), "unicode filename should be preserved")

                fragment = escaping.member_name_for_urn(images[0].urn.value, volume.version, base_urn=volume.urn, use_unicode=True)

                self.assertEqual(arnPathFragment, fragment)
                try:
                    with volume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                        txt = fd.ReadAll()
                        self.assertEqual("helloworldhelloworld", txt, "content should be same")
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
                    src = io.BytesIO("hello")
                    urn = volume.writeLogical(pathName, src, 10)


            with container.Container.openURNtoContainer(container_urn) as volume:
                images = list(volume.images())
                self.assertEqual(1, len(images), "Only one logical image")
                self.assertEqual(pathName, images[0].name(), "unicode filename should be preserved")

                fragment = escaping.member_name_for_urn(images[0].urn.value, volume.version, base_urn=volume.urn, use_unicode=True)

                self.assertEqual(arnPathFragment, fragment)
                try:
                    with volume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                        txt = fd.ReadAll()
                        self.assertEqual("hello", txt, "content should be same")
                except Exception:
                    traceback.print_exc()
                    self.fail()
        except Exception:
            traceback.print_exc()
            self.fail()

        finally:
            os.unlink(containerName)

    def testWindowsUNCLogicalImagePush(self):
        containerName = "/tmp/test-unc.aff4"
        self.createAndReadSinglePathImagePush(containerName, u"\\\\foo\\bar.txt", u"foo/bar.txt")

    def testWindowsUNCLogicalImage(self):
        containerName = "/tmp/test-unc.aff4"
        self.createAndReadSinglePathImage(containerName, u"\\\\foo\\bar.txt", u"foo/bar.txt")

    def testUnixASCIINoSlashLogicalImage(self):
        containerName = "/tmp/test-unix1.aff4"
        self.createAndReadSinglePathImage(containerName, u"foo/bar.txt", u"/foo/bar.txt")

    def testUnixASCIISlashLogicalImage(self):
        containerName = "/tmp/test-unix1.aff4"
        self.createAndReadSinglePathImage(containerName, u"/foo/bar.txt", u"/foo/bar.txt")

    def testUnixUnicodeLogicalImage(self):
        containerName = "/tmp/test-unicodepath.aff4"
        self.createAndReadSinglePathImage(containerName, u"/犬/ネコ.txt", u"/犬/ネコ.txt")

    def testWindowsDriveLogicalImage(self):
        containerName = "/tmp/test-windowsdrive.aff4"
        self.createAndReadSinglePathImage(containerName, u"c:\ネコ.txt", u"/c:/犬/ネコ.txt")

    def testAFF4ReservedSegmentCollision(self):
        containerName = "/tmp/test.aff4"
        try:
            container_urn = rdfvalue.URN.FromFileName(containerName)
            with data_store.MemoryDataStore() as resolver:
                urn = None
                with container.Container.createURN(resolver, container_urn) as volume:
                    src = io.BytesIO("hello")
                    urn = volume.writeLogical(u"information.turtle", src, 10)


            with container.Container.openURNtoContainer(container_urn) as volume:
                images = list(volume.images())
                self.assertEqual(1, len(images), "Only one logical image")
                self.assertEqual("information.turtle", images[0].name(), "information.turtle should be escaped")

                try:
                    with volume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                        txt = fd.ReadAll()
                        self.assertEqual("hello", txt, "escaped file returned")
                except Exception:
                    traceback.print_exc()
                    self.fail("content of information.turtle is wrong")

        except Exception:
            traceback.print_exc()
            self.fail()

        finally:
            os.unlink(containerName)



if __name__ == '__main__':
    unittest.main()