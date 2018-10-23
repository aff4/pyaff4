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
from pyaff4 import rdfvalue
from pyaff4 import aff4_map
from pyaff4.container import Container
from pyaff4 import zip
import unittest, traceback
from pyaff4 import utils
import os, io

"""
Tests logical file creation
"""
class LogicalAppendTest(unittest.TestCase):
    testImagesPath = os.path.join(os.path.dirname(__file__), u"..", u"test_images", u"AFF4-L")


    def setUp(self):
        pass

    def testCreateAndAppendSinglePathImage(self):
        try:
            containerName = "/tmp/test-append.aff4"
            pathA = u"/a.txt"
            pathB = u"/b.txt"

            container_urn = rdfvalue.URN.FromFileName(containerName)
            resolver = data_store.MemoryDataStore()
            urn = None
            with container.Container.createURN(resolver, container_urn) as volume:
                src = io.BytesIO("hello")
                urn = volume.writeLogical(pathA, src, 10)

            urn = None
            with container.Container.openURNtoContainer(container_urn, mode="+") as volume:
                src = io.BytesIO("hello2")
                urn = volume.writeLogical(pathB, src, 12)

            with container.Container.openURNtoContainer(container_urn) as volume:
                images = list(volume.images())
                images.sort()
                self.assertEqual(2, len(images), "Only two logical images")

                fragmentA = escaping.member_name_for_urn(images[0].urn.value, volume.version, base_urn=volume.urn, use_unicode=True)
                fragmentB = escaping.member_name_for_urn(images[1].urn.value, volume.version, base_urn=volume.urn, use_unicode=True)

                self.assertEqual(pathA, fragmentA)
                self.assertEqual(pathB, fragmentB)

                try:
                    with volume.resolver.AFF4FactoryOpen(images[0].urn) as fd:
                        txt = fd.ReadAll()
                        self.assertEqual("hello", txt, "content should be same")
                    with volume.resolver.AFF4FactoryOpen(images[1].urn) as fd:
                        txt = fd.ReadAll()
                        self.assertEqual("hello2", txt, "content should be same")
                except Exception:
                    traceback.print_exc()
                    self.fail()

        except:
            traceback.print_exc()
            self.fail()

        finally:
            os.unlink(containerName)




if __name__ == '__main__':
    unittest.main()