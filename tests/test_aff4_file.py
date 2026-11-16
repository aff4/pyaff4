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

import os
import shutil
import tempfile
import unittest

from pyaff4 import data_store, rdfvalue
from pyaff4.container import Container


class MissingDirectoryTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.directory)

    def testCreatingVolumeInMissingDirectoryFails(self):
        missing = os.path.join(self.directory, "missing")
        filename = os.path.join(missing, "volume.aff4")

        with self.assertRaises(FileNotFoundError) as raised:
            with data_store.MemoryDataStore() as resolver:
                with Container.createURN(resolver, rdfvalue.URN.FromFileName(filename)):
                    pass

        self.assertEqual(filename, raised.exception.filename)
        self.assertFalse(os.path.exists(missing))


if __name__ == "__main__":
    unittest.main()
