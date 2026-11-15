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

import os
import unittest

from pyaff4 import aff4_file
from pyaff4 import data_store
from pyaff4 import lexicon
from pyaff4 import rdfvalue
import tempfile
import traceback

class StreamTest(unittest.TestCase):
    def streamTest(self, stream):
        self.assertEqual(0, stream.TellRead())
        self.assertEqual(0, stream.Size())

        stream.Write(b"hello world")
        self.assertEqual(11, stream.TellWrite())

        stream.SeekRead(0, 0)
        self.assertEqual(0, stream.TellRead())

        self.assertEqual(b"hello world",
                          stream.Read(1000))

        self.assertEqual(11, stream.TellRead())

        stream.SeekRead(-5, 2)
        self.assertEqual(6, stream.TellRead())

        self.assertEqual(b"world",
                          stream.Read(1000))

        stream.SeekWrite(6, 0)
        self.assertEqual(6, stream.TellWrite())

        stream.Write(b"Cruel world")
        stream.SeekRead(0, 0)
        self.assertEqual(0, stream.TellRead())
        self.assertEqual(b"hello Cruel world",
                          stream.Read(1000))

        self.assertEqual(17, stream.TellRead())

        stream.SeekRead(0, 0)

        self.assertEqual(b"he",
                          stream.Read(2))

        stream.SeekWrite(2,0)
        stream.Write(b"I have %d arms and %#x legs." % (2, 1025))
        self.assertEqual(31, stream.TellWrite())

        stream.SeekRead(0, 0)
        self.assertEqual(b"heI have 2 arms and 0x401 legs.",
                          stream.Read(1000))

    def testFileBackedStream(self):
        filename = tempfile.gettempdir() + "/test_filename.zip"
        fileURI = rdfvalue.URN.FromFileName(filename)

        try:
            with data_store.MemoryDataStore() as resolver:
                file_stream = aff4_file.FileBackedObject(
                    resolver, fileURI, None, appendmode="truncate")
                file_stream.LoadFromURN()
                resolver.ObjectCache.Put(file_stream, True)
                with file_stream:
                    self.streamTest(file_stream)
        except:
            traceback.print_exc()
            self.fail()

        finally:
            os.unlink(filename)


if __name__ == '__main__':
    unittest.main()
