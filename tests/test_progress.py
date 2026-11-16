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
"""Progress reporting while writing and verifying logical images."""

import io
import os
import shutil
import tempfile
import unittest

from pyaff4 import aff4, block_hasher, data_store, linear_hasher, rdfvalue
from pyaff4.container import Container

PAYLOAD = os.urandom(4096)


class RecordingProgress(aff4.EmptyProgressContext):
    def __init__(self):
        super().__init__()
        self.reports = []

    def Report(self, readptr):
        self.reports.append(readptr)


class ProgressTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.urn = rdfvalue.URN.FromFileName(os.path.join(self.directory, "volume.aff4"))

    def tearDown(self):
        shutil.rmtree(self.directory)

    def write(self, segment_limit):
        progress = RecordingProgress()
        with data_store.MemoryDataStore() as resolver:
            with Container.createURN(resolver, self.urn) as volume:
                volume.maxSegmentResidentSize = segment_limit
                volume.writeLogicalStream(
                    "file.bin", io.BytesIO(PAYLOAD), len(PAYLOAD), progress=progress
                )
        return progress.reports

    def testZipSegmentWriteReportsBytesWritten(self):
        reports = self.write(segment_limit=len(PAYLOAD))
        self.assertEqual(len(PAYLOAD), reports[-1])

    def testBlockStreamWriteReportsProgress(self):
        self.assertTrue(self.write(segment_limit=1024))

    def testHashReportsBytesRead(self):
        self.write(segment_limit=len(PAYLOAD))
        progress = RecordingProgress()
        with Container.openURNtoContainer(self.urn) as volume:
            hasher = linear_hasher.LinearHasher2(volume.resolver, block_hasher.ValidationListener())
            for image in volume.images():
                hasher.hash(image, progress=progress)
        self.assertEqual(len(PAYLOAD), progress.reports[-1])
        self.assertEqual(sorted(progress.reports), progress.reports)


if __name__ == "__main__":
    unittest.main()
