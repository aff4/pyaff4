# Copyright 2015 Google Inc. All rights reserved.
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
from rdflib import URIRef, XSD, RDF, Literal

from pyaff4.rdfvalue import ARN, FileRef

from pyaff4 import aff4
from pyaff4 import data_store
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import streams
from pyaff4 import version
from pyaff4 import container

import unittest

import io, os


referenceImagesPath = os.path.join(os.path.dirname(__file__), "..", "test_images")
stdLinear = os.path.join(referenceImagesPath, "AFF4Std1a", "Base-Linear.aff4")

class HDTStoreOpenTest(unittest.TestCase):
    def setUp(self):
        self.stdLinearURN = rdfvalue.URN.FromFileName(stdLinear)

    def testOpenPhysicalImageFromHdt(self):
        with container.Container.openURNtoContainer(self.stdLinearURN) as volume:
            resolver = volume.resolver
            subjects = list(resolver.QueryPredicateObject(volume.urn,
                                                     URIRef("http://aff4.org/Schema#diskMake"),
                                                     Literal("Seagate")))
            self.assertEqual(1, len(subjects))
            self.assertEqual(
                subjects[0],
                URIRef("aff4://cf853d0b-5589-4c7c-8358-2ca1572b87eb"))

            for subject in resolver.QueryPredicateObject(volume.urn,
                                                         URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
                                                         URIRef("http://aff4.org/Schema#DiskImage")):
                self.assertEqual(
                    subject,
                    URIRef("aff4://cf853d0b-5589-4c7c-8358-2ca1572b87eb"))

            for subject in resolver.QueryPredicateObject(volume.urn,
                                                         URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
                                                         URIRef("http://aff4.org/Schema#Image")):
                self.assertEqual(
                    subject,
                    URIRef("aff4://cf853d0b-5589-4c7c-8358-2ca1572b87eb"))

            for subject in resolver.QueryPredicateObject(volume.urn,
                                                         URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
                                                         URIRef("http://aff4.org/Schema#ContiguousImage")):
                self.assertEqual(
                    subject,
                    URIRef("aff4://cf853d0b-5589-4c7c-8358-2ca1572b87eb"))

            with resolver.AFF4FactoryOpen(ARN("aff4://c215ba20-5648-4209-a793-1f918c723610")) as imageStream:
                imageStream.SeekRead(0x163)
                res = imageStream.Read(17)
                self.assertEqual(res, b"Invalid partition")

if __name__ == '__main__':
    unittest.main()
