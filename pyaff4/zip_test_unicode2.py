# -*- coding: utf-8 -*-
# Copyright 2019 Schatz Forensic Pty Ltd All rights reserved.
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
#
# Author: Bradley L Schatz bradley@evimetry.com

from __future__ import unicode_literals
import tempfile

from future import standard_library
standard_library.install_aliases()
import os
import unittest

from pyaff4 import data_store
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import zip
from pyaff4 import version


class ZipTest(unittest.TestCase):
    filename = tempfile.gettempdir() + "/aff4_unicode2_test.zip"
    filename_urn = rdfvalue.URN.FromFileName(filename)
    segment_name = "\\犬\\ネコ.txt"
    data1 = b"I am a segment!"

    def setUp(self):
        with data_store.MemoryDataStore() as resolver:
            resolver.Set(lexicon.transient_graph, self.filename_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

            with zip.ZipFile.NewZipFile(resolver, version.aff4v11, self.filename_urn) as zip_file:
                self.volume_urn = zip_file.urn

                with zip_file.CreateZipSegment(self.segment_name, arn=None) as segment:
                    segment.Write(self.data1)


    def tearDown(self):
        try:
            os.unlink(self.filename)
        except (IOError, OSError):
            pass


    def testOpenSegmentByURN(self):
        resolver = data_store.MemoryDataStore()

        # This is required in order to load and parse metadata from this volume
        # into a fresh empty resolver.
        with zip.ZipFile.NewZipFile(resolver, version.aff4v11, self.filename_urn) as zip_file:
            segment_urn = zip_file.urn.Append(self.segment_name, quote=False)
        with resolver.AFF4FactoryOpen(segment_urn) as segment:
            self.assertEquals(segment.Read(1000), self.data1 )

if __name__ == '__main__':
    unittest.main()
