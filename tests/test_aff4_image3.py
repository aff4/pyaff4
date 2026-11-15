# Copyright 2014 Google Inc. All rights reserved.
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
import sys
import tempfile
import os
import io
import unittest

from rdflib import Literal

from pyaff4 import aff4_image
from pyaff4 import data_store
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import zip
from pyaff4 import container
from pyaff4 import aff4


class AFF4ImageTest(unittest.TestCase):
    filename = tempfile.gettempdir() + "/aff4_image_test3.zip"
    filename_urn = rdfvalue.URN.FromFileName(filename)
    image_name = "image.dd"

    def setUp(self):
        try:
            os.unlink(self.filename)
        except (IOError, OSError):
            pass

    def tearDown(self):
        try:
            os.unlink(self.filename)
        except (IOError, OSError):
            pass

    def setUp(self):
        version = container.Version(0, 1, "pyaff4")
        with data_store.MemoryDataStore() as resolver:

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn, appendmode="truncate") as zip_file:
                self.volume_urn = aff4.newARN()
                image_urn = self.volume_urn.Append(self.image_name)

                with container.ZipMemberContainer(resolver, self.volume_urn, zip_file,
                                                  version=version) as member_container:

                    # Use default compression.
                    with aff4_image.AFF4Image.NewAFF4Image(
                        resolver, member_container, image_urn, self.volume_urn) as image:

                        for i in range(1):
                            image.Write(b"Hello world %02d!" % i)


    def testOpenImageByURN(self):
        resolver = data_store.MemoryDataStore()
        version = container.Version(1, 1, "pyaff4")
        # This is required in order to load and parse metadata from this volume
        # into a fresh empty resolver.
        resolver.transient_store.print()

        with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
            volume_arn = rdfvalue.ARN(zip_file.arn_in_comment)
            image_urn = volume_arn.Append(self.image_name)

            with container.ZipMemberContainer(resolver, volume_arn, zip_file,
                                              version=version) as member_container:

                with resolver.AFF4FactoryOpen(image_urn) as image:
                    self.assertEqual(
                        b"Hello world 00!",
                        image.Read(100))

                    self.assertEqual(15, image.Size())


if __name__ == '__main__':
    #logging.getLogger().setLevel(logging.DEBUG)
    unittest.main()
