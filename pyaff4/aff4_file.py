# Copyright 2015 Google Inc. All rights reserved.
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

"""An implementation of AFF4 file backed objects."""
from __future__ import unicode_literals
from future import standard_library
standard_library.install_aliases()
from builtins import str

import logging
import os
import io

from pyaff4 import aff4
from pyaff4 import aff4_utils
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import registry
from pyaff4 import utils

BUFF_SIZE = 64 * 1024


LOGGER = logging.getLogger("pyaff4")


class FileBackedObject(aff4.AFF4Stream):
    def __init__(self,  *args, **kwargs):
        super(FileBackedObject, self).__init__( *args, **kwargs)

    def _GetFilename(self):
        filename = self.resolver.GetUnique(lexicon.transient_graph, self.urn, lexicon.AFF4_FILE_NAME)
        if filename:
            return filename

        # Only file:// URNs are supported.
        if self.urn.Scheme() == "file":
            return self.urn.ToFilename()

    @staticmethod
    def _CreateIntermediateDirectories(components):
        """Recursively create intermediate directories."""
        path = os.sep

        if aff4.WIN32:
            # On windows we do not want a leading \ (e.g. C:\windows not
            # \C:\Windows)
            path = ""

        for component in components:
            path = path + component + os.sep
            if LOGGER.isEnabledFor(logging.INFO):
                LOGGER.info("Creating intermediate directories %s", path)

            if os.isdir(path):
                continue

            # Directory does not exist - Try to make it.
            try:
                aff4_utils.MkDir(path)
                continue
            except IOError as e:
                LOGGER.error(
                    "Unable to create intermediate directory: %s", e)
                raise

    def LoadFromURN(self):
        flags = "rb"

        filename = self._GetFilename()
        if not filename:
            raise IOError("Unable to find storage for %s" % self.urn)

        filename = str(filename)

        directory_components = os.sep.split(filename)
        directory_components.pop(-1)

        mode = self.resolver.GetUnique(lexicon.transient_graph, self.urn, lexicon.AFF4_STREAM_WRITE_MODE)
        if mode == "truncate":
            flags = "w+b"
            #self.resolver.Set(lexicon.transient_graph, self.urn, lexicon.AFF4_STREAM_WRITE_MODE,
            #                 rdfvalue.XSDString("append"))
            self.properties.writable = True
            self._CreateIntermediateDirectories(directory_components)

        elif mode == "append":
            flags = "a+b"
            self.properties.writable = True
            self._CreateIntermediateDirectories(directory_components)

        elif mode == "random":
            flags = "r+b"
            self.properties.writable = True
            self._CreateIntermediateDirectories(directory_components)

        if LOGGER.isEnabledFor(logging.INFO):
            LOGGER.info("Opening file %s", filename)
        self.fd = open(filename, flags)
        try:
            self.fd.seek(0, 2)
            self.size = self.fd.tell()
        except IOError:
            self.properties.sizeable = False
            self.properties.seekable = False

    def Read(self, length):
        if self.fd.tell() != self.readptr:
            self.fd.seek(self.readptr)

        result = self.fd.read(length)
        self.readptr += len(result)
        return result

    def ReadAll(self):
        res = b""
        while True:
            toRead = 32 * 1024
            data = self.Read(toRead)
            if data == None or len(data) == 0:
                # EOF
                return res
            else:
                res += data


    def WriteStream(self, stream, progress=None):
        """Copy the stream into this stream."""
        while True:
            data = stream.read(BUFF_SIZE)
            if not data:
                break

            self.Write(data)
            progress.Report(self.readptr)

    def Write(self, data):
        if LOGGER.isEnabledFor(logging.INFO):
            LOGGER.info("ZipFileSegment.Write %s @ %x[%x]", self.urn, self.writeptr, len(data))
        if not self.properties.writable:
            raise IOError("Attempt to write to read only object")
        self.MarkDirty()

        # On OSX, the following test doesn't work
        # so we need to do the seek every time
        if aff4.MacOS:
            self.fd.seek(self.writeptr)
        else:
            if self.fd.tell() != self.writeptr:
                self.fd.seek(self.writeptr)

        self.fd.write(utils.SmartStr(data))
        # self.fd.flush()

        #self.size = len(data)
        #self.size = len(data)
        self.writeptr += len(data)
        if self.writeptr > self.size:
            self.size = self.writeptr

    def Flush(self):
        if self.IsDirty():
            self.fd.flush()
        super(FileBackedObject, self).Flush()

    def Prepare(self):
        self.readptr = 0

    def Truncate(self):
        self.fd.truncate(0)

    def Trim(self, offset):
        self.fd.truncate(offset)
        self.seek(0, offset)

    def Size(self):
        self.fd.seek(0, 2)
        return self.fd.tell()

    def Close(self):
        self.resolver.flush_callbacks["FileBacking"] = self.CloseFile
        #self.fd.close()

    def CloseFile(self):
        self.fd.close()

def GenericFileHandler(resolver, urn, *args, **kwargs):
    if os.path.isdir(urn.ToFilename()):
        directory_handler = registry.AFF4_TYPE_MAP[lexicon.AFF4_DIRECTORY_TYPE]
        result = directory_handler(resolver)
        resolver.Set(result.urn, lexicon.AFF4_STORED, urn)

        return result

    return FileBackedObject(resolver, urn)

registry.AFF4_TYPE_MAP["file"] = GenericFileHandler
registry.AFF4_TYPE_MAP[lexicon.AFF4_FILE_TYPE] = FileBackedObject


class AFF4MemoryStream(FileBackedObject):

    def __init__(self, *args, **kwargs):
        super(AFF4MemoryStream, self).__init__(*args, **kwargs)
        self.fd = io.BytesIO()
        self.properties.writable = True
