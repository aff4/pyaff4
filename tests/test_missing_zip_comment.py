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
"""Opening zip volumes that do not carry the volume URN in their zip comment."""

import io
import os
import shutil
import tempfile
import unittest
import zipfile

from pyaff4 import data_store, rdfvalue
from pyaff4.container import Container

END_OF_CENTRAL_DIRECTORY = b"PK\x05\x06"
COMMENT_LENGTH_OFFSET = 20


def strip_zip_comment(path):
    with open(path, "rb") as f:
        data = bytearray(f.read())
    end = data.rfind(END_OF_CENTRAL_DIRECTORY)
    data[end + COMMENT_LENGTH_OFFSET : end + COMMENT_LENGTH_OFFSET + 2] = b"\0\0"
    del data[end + COMMENT_LENGTH_OFFSET + 2 :]
    with open(path, "wb") as f:
        f.write(data)


class MissingZipCommentTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.filename = os.path.join(self.directory, "volume.aff4")
        self.urn = rdfvalue.URN.FromFileName(self.filename)

    def tearDown(self):
        shutil.rmtree(self.directory)

    def testOpensWithUrnFromContainerDescription(self):
        with data_store.MemoryDataStore() as resolver:
            with Container.createURN(resolver, self.urn) as volume:
                volume.writeLogicalStream("hello.txt", io.BytesIO(b"hello world"), 11)
                volume_urn = str(volume.urn)
        strip_zip_comment(self.filename)
        with zipfile.ZipFile(self.filename) as z:
            self.assertEqual(b"", z.comment)

        with Container.openURNtoContainer(self.urn) as volume:
            self.assertEqual(volume_urn, str(volume.urn))
            images = list(volume.images())
            self.assertEqual(1, len(images))
            with volume.resolver.AFF4FactoryOpen(images[0].urn) as stream:
                self.assertEqual(b"hello world", stream.Read(100))

    def testZipWithoutVolumeUrnIsRejected(self):
        with zipfile.ZipFile(self.filename, "w") as z:
            z.writestr("readme.txt", "not an AFF4 volume")

        with self.assertRaisesRegex(OSError, "no volume URN in its zip comment or in container"):
            with Container.openURNtoContainer(self.urn):
                pass


if __name__ == "__main__":
    unittest.main()
