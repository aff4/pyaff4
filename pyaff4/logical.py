
import os
import platform
import lexicon
import rdfvalue
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

        p =  platform.system()
        if p == "Windows":
            pass
        elif p == "Darwin":
            # https://forensic4cast.com/2016/10/macos-file-movements/
            size = s.st_size
            local_tz = tzlocal.get_localzone()
            birthTime = datetime.fromtimestamp(s.st_birthtime, local_tz)
            lastWritten = datetime.fromtimestamp(s.st_mtime, local_tz)
            accessed = datetime.fromtimestamp(s.st_atime, local_tz)
            recordChanged = datetime.fromtimestamp(s.st_ctime, local_tz)
            # addedDate  ?? todo
            return MacOSFSMetadata(filename, filename, size, lastWritten, accessed, recordChanged, birthTime)

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


