# Copyright 2016-2018 Schatz Forensic Pty Ltd. All rights reserved.
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
import platform
from pyaff4 import lexicon
from rdflib import Literal, XSD
import tzlocal
from datetime import UTC, datetime
from dateutil.parser import parse
import traceback

if platform.system() == "Linux":
    from pyaff4 import statx

class FSMetadata:
    def __init__(self, urn, name, length):
        self.name = name
        self.length = length
        self.urn = urn

    def store(self, resolver):
        size = Literal(self.length, datatype=XSD.integer)
        resolver.Set(self.urn, self.urn, lexicon.AFF4_STREAM_SIZE, size)
        resolver.Set(self.urn, self.urn, lexicon.standard11.pathName, Literal(self.name))

    @staticmethod
    def createFromTarInfo(filename, tarinfo):
        size = tarinfo.size
        local_tz = tzlocal.get_localzone()
        lastWritten = datetime.fromtimestamp(tarinfo.mtime, local_tz)
        accessed = datetime.fromtimestamp(int(tarinfo.pax_headers["atime"]), local_tz)
        recordChanged = datetime.fromtimestamp(int(tarinfo.pax_headers["ctime"]), local_tz)
        # addedDate  ?? todo
        return ClassicUnixMetadata(filename, filename, size, lastWritten, accessed, recordChanged)

    @staticmethod
    def createFromSFTPAttr(filename, attr):
        size = attr.st_size
        local_tz = tzlocal.get_localzone()
        lastWritten = datetime.fromtimestamp(attr.st_mtime, local_tz)
        accessed = datetime.fromtimestamp(attr.st_atime, local_tz)
        #recordChanged = datetime.fromtimestamp(attr.st_ctime, local_tz)
        # addedDate  ?? todo
        return ClassicUnixMetadata(filename, filename, size, lastWritten, accessed, 0)

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

            sx = statx.statx(filename)
            birthTime = datetime.fromtimestamp(sx.get_btime(), local_tz)
            return LinuxFSMetadata(filename, filename, size, lastWritten, accessed, recordChanged, birthTime)

        raise NotImplementedError(
            f"Reading file system metadata is not supported on {p} ({filename})")

class ClassicUnixMetadata(FSMetadata):
    def __init__(self, urn, name, size, lastWritten, lastAccessed, recordChanged):
        super().__init__(urn, name, size)
        self.lastWritten = lastWritten
        self.lastAccessed = lastAccessed
        self.recordChanged = recordChanged


    def store(self, resolver):
        resolver.Set(self.urn, self.urn, lexicon.AFF4_STREAM_SIZE, Literal(self.length, datatype=XSD.integer))
        resolver.Set(self.urn, self.urn, lexicon.standard11.lastWritten, Literal(self.lastWritten, datatype=XSD.dateTime))
        resolver.Set(self.urn, self.urn, lexicon.standard11.lastAccessed, Literal(self.lastAccessed, datatype=XSD.dateTime))
        resolver.Set(self.urn, self.urn, lexicon.standard11.recordChanged, Literal(self.recordChanged, datatype=XSD.dateTime))

class ModernUnixMetadata(ClassicUnixMetadata):
    def __init__(self, urn, name, size, lastWritten, lastAccessed, recordChanged, birthTime):
        super().__init__(urn, name, size, lastWritten, lastAccessed, recordChanged)
        self.birthTime = birthTime

    def store(self, resolver):
        super().store(resolver)
        resolver.Set(self.urn, self.urn, lexicon.standard11.birthTime, Literal(self.birthTime, datatype=XSD.dateTime))

class LinuxFSMetadata(ModernUnixMetadata):
    def __init__(self, urn, name, size, lastWritten, lastAccessed, recordChanged, birthTime):
        super().__init__(urn, name, size, lastWritten, lastAccessed, recordChanged, birthTime)


class MacOSFSMetadata(ModernUnixMetadata):
    def __init__(self, urn, name, size, lastWritten, lastAccessed, recordChanged, birthTime):
        super().__init__(urn, name, size, lastWritten, lastAccessed, recordChanged, birthTime)

class WindowsFSMetadata(FSMetadata):
    def __init__(self, urn, name, size, lastWritten, lastAccessed, birthTime):
        super().__init__(urn, name, size)
        self.lastWritten = lastWritten
        self.lastAccessed = lastAccessed
        self.birthTime = birthTime

    def store(self, resolver):
        size = Literal(self.length, datatype=XSD.integer)
        resolver.Set(self.urn, self.urn, lexicon.AFF4_STREAM_SIZE, size)
        for attribute, time in (
            (lexicon.standard11.lastWritten, self.lastWritten),
            (lexicon.standard11.lastAccessed, self.lastAccessed),
            (lexicon.standard11.birthTime, self.birthTime),
        ):
            resolver.Set(self.urn, self.urn, attribute, Literal(time, datatype=XSD.dateTime))

def resetTimestampsPosix(destFile, lastWritten, lastAccessed, recordChanged, birthTime):
    if lastWritten is None or lastAccessed is None:
        return
    if lastWritten.value is None or lastAccessed.value is None:
        return
    try:
        lw = parse(lastWritten.value)
        la = parse(lastAccessed.value)
        os.utime(destFile, ((la - epoch).total_seconds(), (lw - epoch).total_seconds()))
    except Exception:
        traceback.print_exc()

# default implementation does nothing at present on non posix environments
def resetTimestampsNone(destFile, lastWritten, lastAccessed, recordChanged, birthTime):
    pass

resetTimestamps = resetTimestampsNone
epoch = datetime(1970, 1, 1, tzinfo=UTC)

p = platform.system()
if p == "Darwin" or p == "Linux":
    resetTimestamps = resetTimestampsPosix