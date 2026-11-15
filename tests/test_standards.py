# Copyright 2016,2017 Schatz Forensic Pty Ltd. All rights reserved.
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

import logging
import os
import io
import unittest

from rdflib import URIRef

from pyaff4 import container
from pyaff4 import data_store
from pyaff4 import lexicon
from pyaff4 import plugins
from pyaff4 import rdfvalue
from pyaff4 import zip
from pyaff4 import hashes
from pyaff4 import version
from pyaff4.rdfvalue import ARN

LOGGER = logging.getLogger("pyaff4")

referenceImagesPath = os.environ.get(
    "REFERENCE_IMAGES",
    os.path.join(os.path.dirname(__file__), "..", "reference_images"))
stdLinear = os.path.join(referenceImagesPath, "AFF4Std", "Base-Linear.aff4")

def conditional_on_images(f):
    if not os.access(stdLinear, os.R_OK):
        LOGGER.info("Test images not cloned into repository. Tests disabled."
                    "To enable them run `git submodule update --init`")

        def _decorator():
            print (f.__name__ + ' has been disabled')

        return _decorator
    return f


class StandardsTest(unittest.TestCase):
    stdLinearURN = rdfvalue.URN.FromFileName(stdLinear)

    #@conditional_on_images
    def testLocateImage(self):
        resolver = data_store.MemoryDataStore()

        with zip.ZipFile.NewZipFile(resolver, version.aff4v10, self.stdLinearURN) as zip_file:
            with container.ZipMemberContainer(resolver, None, zip_file) as member_container:
                for subject in resolver.QueryPredicateObject(member_container.urn,
                                                             URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
                                                             URIRef("http://aff4.org/Schema#DiskImage")):
                    self.assertEqual(
                        subject,
                        URIRef("aff4://cf853d0b-5589-4c7c-8358-2ca1572b87eb"))

                for subject in resolver.QueryPredicateObject(member_container.urn,
                                                             URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
                                                             URIRef("http://aff4.org/Schema#Image")):
                    self.assertEqual(
                        subject,
                        URIRef("aff4://cf853d0b-5589-4c7c-8358-2ca1572b87eb"))

                for subject in resolver.QueryPredicateObject(member_container.urn,
                                                             URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
                                                             URIRef("http://aff4.org/Schema#ContiguousImage")):
                    self.assertEqual(
                        subject,
                        URIRef("aff4://cf853d0b-5589-4c7c-8358-2ca1572b87eb"))

    #@conditional_on_images
    def testReadMap(self):
        resolver = data_store.MemoryDataStore()

        with zip.ZipFile.NewZipFile(resolver, version.aff4v10, self.stdLinearURN) as zip_file:
            with container.ZipMemberContainer(resolver, None, zip_file) as member_container:
                imageStream = resolver.AFF4FactoryOpen(
                    ARN("aff4://c215ba20-5648-4209-a793-1f918c723610"))

                imageStream.SeekRead(0x163)
                res = imageStream.Read(17)
                self.assertEqual(res, b"Invalid partition")

    #@conditional_on_images
    def testReadImageStream(self):
        resolver = data_store.MemoryDataStore()

        with zip.ZipFile.NewZipFile(resolver, version.aff4v10, self.stdLinearURN) as zip_file:
            with container.ZipMemberContainer(resolver, None, zip_file) as member_container:
                mapStream = resolver.AFF4FactoryOpen(
                    ARN("aff4://c215ba20-5648-4209-a793-1f918c723610"))

                mapStream.SeekRead(0x163)
                res = mapStream.Read(17)
                self.assertEqual(res, b"Invalid partition")


if __name__ == '__main__':
    unittest.main()
