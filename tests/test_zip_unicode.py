# -*- coding: utf-8 -*-
#
# Copyright 2018 Schatz Forensic Pty Ltd. All rights reserved.
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
import unittest

from pyaff4 import data_store, escaping
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import zip
from pyaff4.version import Version
import traceback, tempfile

class ZipTest(unittest.TestCase):
    filename = tempfile.gettempdir() + "/aff4_test.zip"
    filename_urn = rdfvalue.URN.FromFileName(filename)
    segment_name = "/犬/ネコ.txt"
    unc_segment_name = "\\\\foo\\bar\\ネコ.txt"
    period_start_segment_name = "./foo/bar/foo.txt"
    data1 = b"I am a segment!"

    def setUp(self):
        version = Version(1, 1, "pyaff4")
        self.segment_filename = escaping.arnPathFragment_from_path(self.segment_name)
        self.unc_segment_filename = escaping.arnPathFragment_from_path(self.unc_segment_name)
        self.period_segment_filename = escaping.arnPathFragment_from_path(self.period_start_segment_name)

        with data_store.MemoryDataStore() as resolver:
            with zip.ZipFile.NewZipFile(resolver, version, self.filename_urn, appendmode="truncate") as zip_file:
                with zip_file.CreateZipSegment(self.segment_filename) as segment:
                    segment.Write(self.data1)

                with zip_file.CreateZipSegment(self.unc_segment_filename) as segment:
                    segment.Write(self.data1)

                with zip_file.CreateZipSegment(self.period_segment_filename) as segment:
                    segment.Write(self.data1)

    def tearDown(self):
        try:
            os.unlink(self.filename)
        except (IOError, OSError):
            pass


    def testOpenSegmentByURN(self):
        try:
            resolver = data_store.MemoryDataStore()

            # This is required in order to load and parse metadata from this volume
            # into a fresh empty resolver.
            with zip.ZipFile.NewZipFile(resolver, Version(1, 1, "pyaff4"), self.filename_urn) as zip_file:
                with zip_file.OpenZipSegment(self.segment_filename) as segment:
                    self.assertEqual(segment.Read(1000), self.data1)
                with zip_file.OpenZipSegment(self.unc_segment_filename) as segment:
                    self.assertEqual(segment.Read(1000), self.data1)
                with zip_file.OpenZipSegment(self.period_segment_filename) as segment:
                    self.assertEqual(segment.Read(1000), self.data1)

        except Exception:
            traceback.print_exc()
            self.fail()

if __name__ == '__main__':
    unittest.main()
