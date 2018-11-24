# Copyright 2016-2018 Schatz Forensic Pty Ltd. All rights reserved.
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
import platform
from pyaff4 import lexicon
from pyaff4 import rdfvalue
import time
import tzlocal
from datetime import datetime

class FSMetadata(object):
    def __init__(self, urn, name, length):
        self.name = name
        self.length = length
        self.urn = urn

    def store(self, resolver):
        resolver.Set(self.urn, rdfvalue.URN(lexicon.size), rdfvalue.XSDInteger(self.length))
        resolver.Set(self.urn, rdfvalue.URN(lexicon.name), rdfvalue.XSDInteger(self.name))

    @staticmethod
    def create(filename):
        s = os.stat(filename)
        p = platform.system()
        local_tz = tzlocal.get_localzone()

        if p == "Windows":
            size = s.st_size
            birthTime = datetime.fromtimestamp(s.st_ctime, local_tz)
            lastWritten = datetime.fromtimestamp(s.st_mtime, local_tz)
            accessed = datetime.fromtimestamp(s.st_atime, local_tz)

            return WindowsFSMetadata(filename, filename, size, lastWritten, accessed, birthTime)
        elif p == "Darwin":
            # https://forensic4cast.com/2016/10/macos-file-movements/
            size = s.st_size
            birthTime = datetime.fromtimestamp(s.st_birthtime, local_tz)
            lastWritten = datetime.fromtimestamp(s.st_mtime, local_tz)
            accessed = datetime.fromtimestamp(s.st_atime, local_tz)
            recordChanged = datetime.fromtimestamp(s.st_ctime, local_tz)
            # addedDate  ?? todo
            return MacOSFSMetadata(filename, filename, size, lastWritten, accessed, recordChanged, birthTime)
        elif p == "Linux":
            size = s.st_size
            # TODO: birthTime
            lastWritten = datetime.fromtimestamp(s.st_mtime, local_tz)
            accessed = datetime.fromtimestamp(s.st_atime, local_tz)
            recordChanged = datetime.fromtimestamp(s.st_ctime, local_tz)
            return LinuxFSMetadata(filename, filename, size, lastWritten, accessed, recordChanged)


class LinuxFSMetadata(FSMetadata):
    def __init__(self, urn, name, size, lastWritten, lastAccessed, recordChanged):
        super(LinuxFSMetadata, self).__init__(urn, name, size)
        self.lastWritten = lastWritten
        self.lastAccessed = lastAccessed
        self.recordChanged = recordChanged

    def store(self, resolver):
        resolver.Set(self.urn, rdfvalue.URN(lexicon.AFF4_STREAM_SIZE), rdfvalue.XSDInteger(self.length))
        resolver.Set(self.urn, rdfvalue.URN(lexicon.standard11.lastWritten), rdfvalue.XSDDateTime(self.lastWritten))
        resolver.Set(self.urn, rdfvalue.URN(lexicon.standard11.lastAccessed), rdfvalue.XSDDateTime(self.lastAccessed))
        resolver.Set(self.urn, rdfvalue.URN(lexicon.standard11.recordChanged), rdfvalue.XSDDateTime(self.recordChanged))


class MacOSFSMetadata(FSMetadata):
    def __init__(self, urn, name, size, lastWritten, lastAccessed, recordChanged, birthTime):
        super(MacOSFSMetadata, self).__init__(urn, name, size)
        self.lastWritten = lastWritten
        self.lastAccessed = lastAccessed
        self.recordChanged = recordChanged
        self.birthTime = birthTime

    def store(self, resolver):
        resolver.Set(self.urn, rdfvalue.URN(lexicon.AFF4_STREAM_SIZE), rdfvalue.XSDInteger(self.length))
        resolver.Set(self.urn, rdfvalue.URN(lexicon.standard11.lastWritten), rdfvalue.XSDDateTime(self.lastWritten))
        resolver.Set(self.urn, rdfvalue.URN(lexicon.standard11.lastAccessed), rdfvalue.XSDDateTime(self.lastAccessed))
        resolver.Set(self.urn, rdfvalue.URN(lexicon.standard11.recordChanged), rdfvalue.XSDDateTime(self.recordChanged))
        resolver.Set(self.urn, rdfvalue.URN(lexicon.standard11.birthTime), rdfvalue.XSDDateTime(self.birthTime))


class WindowsFSMetadata(FSMetadata):
    def __init__(self, urn, name, size, lastWritten, lastAccessed, birthTime):
        super(WindowsFSMetadata, self).__init__(urn, name, size)
        self.lastWritten = lastWritten
        self.lastAccessed = lastAccessed
        self.birthTime = birthTime

    def store(self, resolver):
        resolver.Set(self.urn, rdfvalue.URN(lexicon.AFF4_STREAM_SIZE), rdfvalue.XSDInteger(self.length))
        resolver.Set(self.urn, rdfvalue.URN(lexicon.standard11.lastWritten), rdfvalue.XSDDateTime(self.lastWritten))
        resolver.Set(self.urn, rdfvalue.URN(lexicon.standard11.lastAccessed), rdfvalue.XSDDateTime(self.lastAccessed))
        resolver.Set(self.urn, rdfvalue.URN(lexicon.standard11.birthTime), rdfvalue.XSDDateTime(self.birthTime))
