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
"""Reading images whose bevies are named the way Magnet AXIOM names them.

There is no AXIOM-written sample here: the volume is written by pyaff4 and then rewritten with
AXIOM's bevy names (the original path, then a backslash and the bevy number), AXIOMProcess as the
tool, and the interim AFF4-L path predicate. It checks pyaff4's naming rule, not AXIOM's output.
"""

import io
import os
import shutil
import tempfile
import unittest
import zipfile

from pyaff4 import data_store, rdfvalue
from pyaff4.container import Container

ORIGINAL_PATH = "C:\\Users\\a b\\file.bin"
PYAFF4_BEVY_PREFIX = "/C:/Users/a b/file.bin/"
AXIOM_BEVY_PREFIX = "C%3A\\Users\\a b\\file.bin\\"


class AxiomBevyNamesTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.payload = os.urandom(3000)

    def tearDown(self):
        shutil.rmtree(self.directory)

    def write_axiom_style_volume(self):
        written = os.path.join(self.directory, "pyaff4.aff4")
        with data_store.MemoryDataStore() as resolver:
            with Container.createURN(resolver, rdfvalue.URN.FromFileName(written)) as volume:
                # Below the payload size, so the file is written as a bevied image.
                volume.maxSegmentResidentSize = 1024
                volume.writeLogicalStream(
                    ORIGINAL_PATH, io.BytesIO(self.payload), len(self.payload)
                )

        axiom = os.path.join(self.directory, "axiom.aff4")
        with zipfile.ZipFile(written) as source, zipfile.ZipFile(axiom, "w") as target:
            target.comment = source.comment
            for member in source.infolist():
                name, data = member.filename, source.read(member)
                if name.startswith("information.hdt"):
                    # AXIOM writes no HDT, and readers would prefer it to the rewritten turtle.
                    continue
                if name.startswith(PYAFF4_BEVY_PREFIX):
                    name = AXIOM_BEVY_PREFIX + name[len(PYAFF4_BEVY_PREFIX) :]
                elif name == "version.txt":
                    data = data.replace(b"tool=pyaff4", b"tool=AXIOMProcess")
                elif name == "information.turtle":
                    data = data.replace(b"originalFileName", b"originalPathName")
                target.writestr(name, data)
        return rdfvalue.URN.FromFileName(axiom)

    def testReadsImageFromAxiomNamedBevies(self):
        with Container.openURNtoContainer(self.write_axiom_style_volume()) as volume:
            self.assertEqual("AXIOMProcess", volume.version.tool)
            images = list(volume.images())
            self.assertEqual(1, len(images))
            with volume.resolver.AFF4FactoryOpen(images[0].urn, version=volume.version) as stream:
                self.assertEqual(self.payload, stream.read(len(self.payload) + 1))


if __name__ == "__main__":
    unittest.main()
