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
from pyaff4 import plugins
from pyaff4 import aff4


class AFF4ImageTest(unittest.TestCase):
    filename = tempfile.gettempdir() + "/aff4_image_test.zip"
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
            # resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
            #              Literal("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn, appendmode="truncate") as zip_file:
                self.volume_urn = aff4.newARN()
                image_urn = self.volume_urn.Append(self.image_name)

                with container.ZipMemberContainer(resolver, self.volume_urn, zip_file, version=version) as member_container:
                    # Use default compression.
                    with aff4_image.AFF4Image.NewAFF4Image(
                        resolver, member_container, image_urn, self.volume_urn) as image:
                        image.chunk_size = 10
                        image.chunks_per_segment = 3

                        for i in range(100):
                            image.Write(b"Hello world %02d!" % i)

                        self.image_urn = image.urn

                    # Write a snappy compressed image.
                    self.image_urn_2 = self.image_urn.Append("2")
                    with aff4_image.AFF4Image.NewAFF4Image(
                        resolver, member_container, self.image_urn_2, self.volume_urn) as image_2:
                        image_2.setCompressionMethod(lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY)
                        image_2.Write(b"This is a test")

                    # Use streaming API to write image.
                    self.image_urn_3 = self.image_urn.Append("3")
                    with aff4_image.AFF4Image.NewAFF4Image(
                        resolver, member_container, self.image_urn_3, self.volume_urn) as image:
                        image.chunk_size = 10
                        image.chunks_per_segment = 3
                        stream = io.BytesIO()
                        for i in range(100):
                            stream.write(b"Hello world %02d!" % i)

                        stream.seek(0)
                        image.WriteStream(stream)
                    print()


    def testOpenImageByURN(self):
        resolver = data_store.MemoryDataStore()
        version = container.Version(1, 1, "pyaff4")
        # This is required in order to load and parse metadata from this volume
        # into a fresh empty resolver.
        resolver.transient_store.print()

        with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn) as zip_file:
            resolver.transient_store.print(out=sys.stdout)
            resolver.store.print(out=sys.stdout)

            with container.ZipMemberContainer(resolver, None, zip_file) as member_container:
                resolver.transient_store.print(out=sys.stdout)
                resolver.store.print(out=sys.stdout)
                image_urn = member_container.urn.Append(self.image_name)

                with resolver.AFF4FactoryOpen(image_urn) as image:
                    self.assertEqual(image.chunk_size, 10)
                    self.assertEqual(image.chunks_per_segment, 3)
                    self.assertEqual(
                        b"Hello world 00!Hello world 01!Hello world 02!Hello world 03!" +
                        b"Hello world 04!Hello world 05!Hello worl",
                        image.Read(100))

                    self.assertEqual(1500, image.Size())

                # Now test snappy decompression.
                with resolver.AFF4FactoryOpen(self.image_urn_2) as image_2:
                    self.assertEqual(
                        resolver.GetUnique(zip_file.urn, image_2.urn, lexicon.AFF4_IMAGE_COMPRESSION),
                        lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY)

                    data = image_2.Read(100)
                    self.assertEqual(data, b"This is a test")

                # Now test streaming API image.
                with resolver.AFF4FactoryOpen(self.image_urn_3) as image_3:
                    self.assertEqual(image_3.chunk_size, 10)
                    self.assertEqual(image_3.chunks_per_segment, 3)
                    self.assertEqual(
                        b"Hello world 00!Hello world 01!Hello world 02!Hello world 03!"+
                        b"Hello world 04!Hello world 05!Hello worl",
                        image_3.Read(100))


if __name__ == '__main__':
    #logging.getLogger().setLevel(logging.DEBUG)
    unittest.main()
