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

from pyaff4 import data_store
from pyaff4 import container
from pyaff4 import logical
from pyaff4 import escaping
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import linear_hasher
from pyaff4.container import Container
from pyaff4 import hashes
import unittest, traceback
from pyaff4 import utils
import os, tempfile

"""
Tests logical file creation
"""



class DedupeTest(unittest.TestCase):
    testImagesPath = os.path.join(os.path.dirname(__file__), u"..", u"test_images", u"AFF4-L")
    containerName = tempfile.gettempdir() + "/test-append-dedup.aff4"

    def setUp(self):
        pass

    def onValidHash(self, typ, hash, imageStreamURI):
        self.assertTrue(True)

    def onInvalidHash(self, typ, hasha, hashb, streamURI):
        self.fail()

    def testCreateAndAppendSinglePathImage(self):
        try:
            try:
                os.unlink(self.containerName)
            except:
                pass

            container_urn = rdfvalue.URN.FromFileName(self.containerName)
            resolver = data_store.MemoryDataStore()
            urn = None

            frag1path = os.path.join(self.testImagesPath, "paper-hash_based_disk_imaging_using_aff4.pdf.frag.1")

            with container.Container.createURN(resolver, container_urn) as volume:
                with open(frag1path, "rb") as src:
                    stream = linear_hasher.StreamHasher(src, [lexicon.HASH_SHA1])
                    urn = volume.writeLogicalStreamHashBased(frag1path, stream, 32768, False)
                    for h in stream.hashes:
                        hh = hashes.newImmutableHash(h.hexdigest(), stream.hashToType[h])
                        self.assertEqual("deb3fa3b60c6107aceb97f684899387c78587eae", hh.value)
                        resolver.Add(volume.urn, urn, rdfvalue.URN(lexicon.standard.hash), hh)

            frag2path = os.path.join(self.testImagesPath, "paper-hash_based_disk_imaging_using_aff4.pdf.frag.2")

            with container.Container.openURNtoContainer(container_urn, mode="+") as volume:
                with open(frag2path, "rb") as src:
                    stream = linear_hasher.StreamHasher(src, [lexicon.HASH_SHA1, lexicon.HASH_MD5 ])
                    urn = volume.writeLogicalStreamHashBased(frag2path, stream, 2*32768, False)
                    for h in stream.hashes:
                        hh = hashes.newImmutableHash(h.hexdigest(), stream.hashToType[h])
                        resolver.Add(volume.urn, urn, rdfvalue.URN(lexicon.standard.hash), hh)

            with container.Container.openURNtoContainer(container_urn) as volume:
                images = list(volume.images())
                images = sorted(images, key=lambda x: utils.SmartUnicode(x.pathName), reverse=False)
                self.assertEqual(2, len(images), "Only two logical images")

                fragmentA = escaping.member_name_for_urn(images[0].urn.value, volume.version, base_urn=volume.urn, use_unicode=True)
                fragmentB = escaping.member_name_for_urn(images[1].urn.value, volume.version, base_urn=volume.urn, use_unicode=True)

                self.assertTrue(fragmentA.endswith("paper-hash_based_disk_imaging_using_aff4.pdf.frag.1"))
                self.assertTrue(fragmentB.endswith("paper-hash_based_disk_imaging_using_aff4.pdf.frag.2"))

                hasher = linear_hasher.LinearHasher2(volume.resolver, self)
                for image in volume.images():
                    print("\t%s <%s>" % (image.name(), image.urn))
                    hasher.hash(image)

        except:
            traceback.print_exc()
            self.fail()

        finally:
            #os.unlink(containerName)
            pass




if __name__ == '__main__':
    unittest.main()