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
from pyaff4 import plugins


class AFF4ImageTest(unittest.TestCase):
    filename = tempfile.gettempdir() + "/aff4_image_test2.zip"
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



    #@unittest.skip
    def testLargerThanBevyWrite(self):
        version = container.Version(0, 1, "pyaff4")

        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                self.image_urn = self.volume_urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with aff4_image.AFF4Image.NewAFF4Image(resolver, self.image_urn_2, self.volume_urn) as image:
                    image.chunk_size = 5
                    image.chunks_per_segment = 2
                    image.Write(b"abcdeabcdea")
                    self.assertEquals(b"abcde", image.Read(5))

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
                image_urn = zip_file.urn.Append(self.image_name)

                self.image_urn_2 = self.image_urn.Append("2")
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image:
                    self.assertEquals(11, image.Size())
                    self.assertEqual(b"abcdeabcdea", image.ReadAll())

if __name__ == '__main__':
    #logging.getLogger().setLevel(logging.DEBUG)
    unittest.main()
