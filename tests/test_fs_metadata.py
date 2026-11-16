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
"""File system metadata captured for logical images (pyaff4.logical)."""

import tarfile
import unittest
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest import mock

from rdflib import XSD, Literal

from pyaff4 import data_store, lexicon, logical, rdfvalue

URN = rdfvalue.ARN("aff4://5f1b2c4e-0000-4000-8000-000000000000//file.txt")
WRITTEN = datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)
ACCESSED = datetime(2024, 2, 3, 4, 5, 6, tzinfo=UTC)
BORN = datetime(2023, 12, 1, 0, 0, 0, tzinfo=UTC)


def stored(metadata, attribute):
    with data_store.MemoryDataStore() as resolver:
        metadata.store(resolver)
        return resolver.GetUnique(URN, URN, attribute)


class StoreTest(unittest.TestCase):
    def testBaseMetadataStoresSizeAndPathName(self):
        metadata = logical.FSMetadata(URN, "/evidence/file.txt", 42)
        self.assertEqual(
            Literal(42, datatype=XSD.integer), stored(metadata, lexicon.AFF4_STREAM_SIZE)
        )
        self.assertEqual(
            Literal("/evidence/file.txt"), stored(metadata, lexicon.standard11.pathName)
        )

    def testWindowsMetadataStoresSizeAndTimes(self):
        metadata = logical.WindowsFSMetadata(URN, "C:\\file.txt", 7, WRITTEN, ACCESSED, BORN)
        expected = {
            lexicon.AFF4_STREAM_SIZE: Literal(7, datatype=XSD.integer),
            lexicon.standard11.lastWritten: Literal(WRITTEN, datatype=XSD.dateTime),
            lexicon.standard11.lastAccessed: Literal(ACCESSED, datatype=XSD.dateTime),
            lexicon.standard11.birthTime: Literal(BORN, datatype=XSD.dateTime),
        }
        for attribute, value in expected.items():
            with self.subTest(attribute=attribute):
                self.assertEqual(value, stored(metadata, attribute))


class ConstructorTest(unittest.TestCase):
    def testFromTarInfo(self):
        info = tarfile.TarInfo("file.txt")
        info.size = 11
        info.mtime = WRITTEN.timestamp()
        info.pax_headers = {
            "atime": str(int(ACCESSED.timestamp())),
            "ctime": str(int(BORN.timestamp())),
        }
        metadata = logical.FSMetadata.createFromTarInfo("file.txt", info)
        self.assertIsInstance(metadata, logical.ClassicUnixMetadata)
        self.assertEqual(
            (11, WRITTEN, ACCESSED, BORN),
            (metadata.length, metadata.lastWritten, metadata.lastAccessed, metadata.recordChanged),
        )

    def testFromSFTPAttr(self):
        attr = SimpleNamespace(
            st_size=11, st_mtime=WRITTEN.timestamp(), st_atime=ACCESSED.timestamp()
        )
        metadata = logical.FSMetadata.createFromSFTPAttr("file.txt", attr)
        self.assertIsInstance(metadata, logical.ClassicUnixMetadata)
        self.assertEqual(
            (11, WRITTEN, ACCESSED), (metadata.length, metadata.lastWritten, metadata.lastAccessed)
        )

    def testCreateRejectsUnsupportedPlatform(self):
        with mock.patch.object(logical.platform, "system", return_value="FreeBSD"):
            with self.assertRaisesRegex(NotImplementedError, "not supported on FreeBSD"):
                logical.FSMetadata.create(__file__)


if __name__ == "__main__":
    unittest.main()
