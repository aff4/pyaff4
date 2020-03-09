# -*- coding: utf-8 -*-
#
# Copyright 2018 Schatz Forensic Pty Ltd. All rights reserved.
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

from __future__ import unicode_literals
from future import standard_library
standard_library.install_aliases()
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
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, Version(1, 1, "pyaff4"), self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn
                segment_urn = self.volume_urn.Append(escaping.arnPathFragment_from_path(self.segment_name), quote=False)

                with zip_file.CreateMember(segment_urn) as segment:
                    segment.Write(self.data1)

                unc_segment_urn = self.volume_urn.Append(escaping.arnPathFragment_from_path(self.unc_segment_name), quote=False)

                with zip_file.CreateMember(unc_segment_urn) as segment:
                    segment.Write(self.data1)

                period_start_segment_urn = self.volume_urn.Append(self.period_start_segment_name, quote=False)

                with zip_file.CreateMember(period_start_segment_urn) as segment:
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
                segment_urn = zip_file.urn.Append(escaping.arnPathFragment_from_path(self.segment_name), quote=False)
                unc_segment_urn = zip_file.urn.Append(escaping.arnPathFragment_from_path(self.unc_segment_name), quote=False)
                period_start_segment_urn = self.volume_urn.Append(
                    escaping.arnPathFragment_from_path(self.period_start_segment_name), quote=False)

            with resolver.AFF4FactoryOpen(segment_urn) as segment:
                self.assertEquals(segment.Read(1000), self.data1 )
            with resolver.AFF4FactoryOpen(unc_segment_urn) as segment:
                self.assertEquals(segment.Read(1000), self.data1 )
            with resolver.AFF4FactoryOpen(unc_segment_urn) as segment:
                self.assertEquals(segment.Read(1000), self.data1)

        except Exception:
            traceback.print_exc()
            self.fail()

if __name__ == '__main__':
    unittest.main()
