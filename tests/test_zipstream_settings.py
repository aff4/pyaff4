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
"""How a logical container stores files: as zip streams or bevied images, compressed or not."""

import io
import os
import shutil
import tempfile
import unittest
import zipfile

from pyaff4 import data_store, lexicon, rdfvalue, zip
from pyaff4.container import Container

SMALL = b"small file"
LARGE = os.urandom(4096)
# Below LARGE's size, so that LARGE is written as a bevied image unless zip streams are forced.
SEGMENT_LIMIT = 1024


class ZipstreamSettingsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.filename = os.path.join(self.directory, "volume.aff4")
        self.urn = rdfvalue.URN.FromFileName(self.filename)

    def tearDown(self):
        shutil.rmtree(self.directory)

    def write(self, **settings):
        with data_store.MemoryDataStore() as resolver:
            with Container.createURN(resolver, self.urn, **settings) as volume:
                volume.maxSegmentResidentSize = SEGMENT_LIMIT
                volume.writeLogicalStream("small.txt", io.BytesIO(SMALL), len(SMALL))
                volume.writeLogicalStream("large.bin", io.BytesIO(LARGE), len(LARGE))

    def members(self):
        with zipfile.ZipFile(self.filename) as z:
            return {info.filename: info.compress_type for info in z.infolist()}

    def assertReadsBack(self):
        with Container.openURNtoContainer(self.urn) as volume:
            contents = {}
            for image in volume.images():
                with volume.resolver.AFF4FactoryOpen(image.urn) as stream:
                    contents[image.name()] = stream.read(len(LARGE) + 1)
        self.assertEqual({"small.txt": SMALL, "large.bin": LARGE}, contents)

    def testDefaultsDeflateSmallFilesAndBevyLargeOnes(self):
        self.write()
        members = self.members()
        self.assertEqual(zipfile.ZIP_DEFLATED, members["/small.txt"])
        self.assertNotIn("/large.bin", members)
        self.assertIn("/large.bin/00000000", members)
        self.assertReadsBack()

    def testStoredCompression(self):
        self.write(zipstream_compression_method=zip.ZIP_STORED)
        members = self.members()
        self.assertEqual(zipfile.ZIP_STORED, members["/small.txt"])
        self.assertIn("/large.bin/00000000", members)
        self.assertReadsBack()

    def testAlwaysWriteZipstreamsStored(self):
        self.write(zipstream_compression_method=zip.ZIP_STORED, always_write_zipstreams=True)
        members = self.members()
        self.assertEqual(zipfile.ZIP_STORED, members["/small.txt"])
        self.assertEqual(zipfile.ZIP_STORED, members["/large.bin"])
        self.assertFalse([name for name in members if name.startswith("/large.bin/")])
        with zipfile.ZipFile(self.filename) as z:
            self.assertEqual(LARGE, z.read("/large.bin"))
        self.assertReadsBack()

    def testNewLogicalStreamFollowsSettings(self):
        with data_store.MemoryDataStore() as resolver:
            with Container.createURN(
                resolver,
                self.urn,
                zipstream_compression_method=zip.ZIP_STORED,
                always_write_zipstreams=True,
            ) as volume:
                volume.maxSegmentResidentSize = SEGMENT_LIMIT
                with volume.newLogicalStream("large.bin", len(LARGE)) as writer:
                    writer.Write(LARGE)
        self.assertEqual(zipfile.ZIP_STORED, self.members()["/large.bin"])

    def testLexiconStoredMeansZipStored(self):
        self.write(zipstream_compression_method=lexicon.AFF4_IMAGE_COMPRESSION_STORED)
        self.assertEqual(zipfile.ZIP_STORED, self.members()["/small.txt"])
        self.assertReadsBack()

    def testRejectsUnsupportedCompressionBeforeCreatingFile(self):
        with data_store.MemoryDataStore() as resolver:
            with self.assertRaisesRegex(ValueError, "must be zip.ZIP_DEFLATE, zip.ZIP_STORED or"):
                Container.createURN(
                    resolver,
                    self.urn,
                    zipstream_compression_method=lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY,
                )
        self.assertFalse(os.path.exists(self.filename))

    def testRejectsSettingsForOtherContainerTypes(self):
        for kind in ({"encryption": True}, {"hashbased": True}):
            for setting in (
                {"zipstream_compression_method": zip.ZIP_STORED},
                {"always_write_zipstreams": True},
            ):
                with self.subTest(**kind, **setting):
                    with data_store.MemoryDataStore() as resolver:
                        with self.assertRaisesRegex(ValueError, "only apply to logical"):
                            Container.createURN(resolver, self.urn, **kind, **setting)
                    self.assertFalse(os.path.exists(self.filename))


if __name__ == "__main__":
    unittest.main()
