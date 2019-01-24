from __future__ import unicode_literals
# Copyright 2014 Google Inc. All rights reserved.
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

from pyaff4 import data_store
from pyaff4 import lexicon
from pyaff4 import rdfvalue
import tempfile
import traceback

class StreamTest(unittest.TestCase):
    def streamTest(self, stream):
        self.assertEquals(0, stream.TellRead())
        self.assertEquals(0, stream.Size())

        stream.Write(b"hello world")
        self.assertEquals(11, stream.TellWrite())

        stream.SeekRead(0, 0)
        self.assertEquals(0, stream.TellRead())

        self.assertEquals(b"hello world",
                          stream.Read(1000))

        self.assertEquals(11, stream.TellRead())

        stream.SeekRead(-5, 2)
        self.assertEquals(6, stream.TellRead())

        self.assertEquals(b"world",
                          stream.Read(1000))

        stream.SeekWrite(6, 0)
        self.assertEquals(6, stream.TellWrite())

        stream.Write(b"Cruel world")
        stream.SeekRead(0, 0)
        self.assertEquals(0, stream.TellRead())
        self.assertEquals(b"hello Cruel world",
                          stream.Read(1000))

        self.assertEquals(17, stream.TellRead())

        stream.SeekRead(0, 0)

        self.assertEquals(b"he",
                          stream.Read(2))

        stream.SeekWrite(2,0)
        stream.Write(b"I have %d arms and %#x legs." % (2, 1025))
        self.assertEquals(31, stream.TellWrite())

        stream.SeekRead(0, 0)
        self.assertEquals(b"heI have 2 arms and 0x401 legs.",
                          stream.Read(1000))

    def testFileBackedStream(self):
        filename = tempfile.gettempdir() + "/test_filename.zip"
        fileURI = rdfvalue.URN.FromFileName(filename)

        try:
            with data_store.MemoryDataStore() as resolver:
                resolver.Set(lexicon.transient_graph, fileURI, lexicon.AFF4_STREAM_WRITE_MODE,
                         rdfvalue.XSDString("truncate"))

                with resolver.AFF4FactoryOpen(fileURI) as file_stream:
                    self.streamTest(file_stream)
        except:
            traceback.print_exc()
            self.fail()

        finally:
            os.unlink(filename)


if __name__ == '__main__':
    unittest.main()
