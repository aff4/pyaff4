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
    "TEST_IMAGES",
    os.path.join(os.path.dirname(__file__), "..", "test_images"))
streamless_image_path = os.path.join(referenceImagesPath, "AFF4-L", "streamless-image.aff4")

def conditional_on_images(f):
    if not os.access(streamless_image_path, os.R_OK):
        LOGGER.info("test_images/AFF4-L/streamless-image.aff4 is missing. Tests disabled.")

        def _decorator():
            print (f.__name__ + ' has been disabled')

        return _decorator
    return f


class StreamlessImageTest(unittest.TestCase):
    streamless_image = rdfvalue.URN.FromFileName(streamless_image_path)

    #@conditional_on_images
    def testReadImageStream(self):
        resolver = data_store.MemoryDataStore()

        with zip.ZipFile.NewZipFile(resolver, version.aff4v10, self.streamless_image) as zip_file:
            with container.ZipMemberContainer(resolver, None, zip_file) as member_container:
                stream = resolver.AFF4FactoryOpen(
                    ARN("aff4://8394820b-89cf-4b18-aca7-12dfdf81cfeb"))

                self.assertEqual(0,stream.Size())
                res = stream.Read(17)
                self.assertEqual(0, len(res))


if __name__ == '__main__':
    unittest.main()
