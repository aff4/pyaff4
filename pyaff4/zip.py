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

"""An implementation of the ZipFile based AFF4 volume."""
import logging
import io
import zlib
import struct

from rdflib import Literal, URIRef
from rdflib.namespace import XSD

from pyaff4 import aff4
from pyaff4 import aff4_file
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import registry
from pyaff4 import struct_parser
from pyaff4.aff4 import MemberContainer
from pyaff4.aff4_file import FileBackedObject
from pyaff4 import escaping, hexdump
from pyaff4.version import Version, basic_zip, parseProperties

LOGGER = logging.getLogger("pyaff4")

# Compression modes we support inside Zip files (Note this is not the same as
# the aff4_image compression.
ZIP_STORED = 0
ZIP_DEFLATE = 8

# CRC-32 field offsets in the local file header and the central directory file header, and the
# general-purpose flag saying the CRC is in a data descriptor after the data (APPNOTE 4.3.7-4.3.9).
LOCAL_HEADER_CRC_OFFSET = 14
CD_ENTRY_CRC_OFFSET = 16
DATA_DESCRIPTOR_FLAG = 1 << 3
DATA_DESCRIPTOR_SIGNATURE = b"PK\x07\x08"
# The field size at which we switch to zip64 semantics.
ZIP32_MAX_SIZE = 2**32 -1

BUFF_SIZE = 64 * 1024

# Flag for debugging zip (uses pre Zip64 so we can open using more Zip tools. Should be false for production.
ZIP_DEBUG = False

# Use unicode filenames per Appendix D of APPNOTE.TXT ( bit 11 EFS)
# produces zips that are openable correctly with Windows Explorer, WinRAR, and 7-ZIP
#   incompatible with MacOS shell compressor and doesnt display will with unzip (infozip)
USE_UNICODE = True

class UnknownZipEntity(Exception):
    pass


class EndCentralDirectory(struct_parser.CreateStruct(
        "EndCentralDirectory_t",
        definition="""
        uint32_t magic = 0x6054b50;
        uint16_t number_of_this_disk = 0;
        uint16_t disk_with_cd = 0;
        uint16_t total_entries_in_cd_on_disk;
        uint16_t total_entries_in_cd;
        uint32_t size_of_cd = 0xFFFFFFFF;
        uint32_t offset_of_cd = 0xFFFFFFFF;
        uint16_t comment_len = 0;
        """)):

    magic_string = b'PK\x05\x06'

    def IsValid(self):
        return self.magic == 0x6054b50

    @classmethod
    def FromBuffer(cls, buffer):
        """Instantiate an EndCentralDirectory from this buffer."""
        # Not enough data to contain an EndCentralDirectory
        if len(buffer) > cls.sizeof():
            # Scan the buffer backwards for an End of Central Directory magic
            end = len(buffer) - cls.sizeof() + 4
            while True:
                index = buffer.rfind(cls.magic_string, 0, end)
                if index < 0:
                    break

                end_cd = cls(buffer[index:])
                if end_cd.IsValid():
                    return end_cd, index

                end = index

        raise IOError("Unable to find EndCentralDirectory")


class CDFileHeader(struct_parser.CreateStruct(
        "CDFileHeader_t",
        """
        uint32_t magic = 0x2014b50;
        uint16_t version_made_by = 0x317;
        uint16_t version_needed = 0x14;
        uint16_t flags = 0x8;
        uint16_t compression_method;
        uint16_t dostime;
        uint16_t dosdate;
        uint32_t crc32;
        uint32_t compress_size = 0xFFFFFFFF;
        uint32_t file_size = 0xFFFFFFFF;
        uint16_t file_name_length;
        uint16_t extra_field_len = 0;
        uint16_t file_comment_length = 0;
        uint16_t disk_number_start = 0;
        uint16_t internal_file_attr = 0;
        uint32_t external_file_attr = 0o644 << 16L;
        uint32_t relative_offset_local_header = 0xffffffff;
        """)):
    def IsValid(self):
        return self.magic == 0x2014b50


class ZipFileHeader(struct_parser.CreateStruct(
        "ZipFileHeader_t",
        """
        uint32_t magic = 0x4034b50;
        uint16_t version = 0x14;
        uint16_t flags = 0x8;
        uint16_t compression_method;
        uint16_t lastmodtime;
        uint16_t lastmoddate;
        uint32_t crc32;
        uint32_t compress_size;
        uint32_t file_size;
        uint16_t file_name_length;
        uint16_t extra_field_len = 0;
        """)):

    def IsValid(self):
        return self.magic == 0x4034b50

# see APPNOTE.txt 4.5.3 -Zip64 Extended Information Extra Field (0x0001):
class Zip64FileHeaderExtensibleField:
    fields = [
        ["uint16_t", "header_id", 1],
        ["uint16_t", "data_size", 0],
        ["uint64_t", "file_size", None],
        ["uint64_t", "compress_size", None],
        ["uint64_t", "relative_offset_local_header", None],
        ["uint32_t", "disk_number_start", None]
    ]

    def __init__(self):
        # Set() writes into the rows, so each instance needs its own copy of them.
        self.fields = [list(row) for row in self.fields]

    def format_string(self):
        return "<" + "".join(
            [struct_parser.format_string_map[t]
             for t, _, d in self.fields if d is not None])

    def sizeof(self):
        """Calculate the total size of the header."""
        return struct.calcsize(self.format_string())

    def empty(self):
        return [] == [d for _, _, d in self.fields[2:] if d is not None]

    def Pack(self):
        # Size of extra less the header.
        self.Set("data_size", self.sizeof() - 4)
        return struct.pack(self.format_string(),
                           *[v for t, _, v in self.fields if v is not None])

    def Get(self, field):
        for row in self.fields:
            if row[1] == field:
                return row[2]

        raise AttributeError("Unknown field %s." % field)

    def Set(self, field, value):
        for row in self.fields:
            if row[1] == field:
                row[2] = value
                return
        raise AttributeError("Unknown field %s." % field)


    @classmethod
    def FromBuffer(cls, fileRecord, buffer):
        result = cls()
        result.header_id = struct.unpack("H", buffer[0:2])[0]
        if result.header_id != 1:
            raise UnknownZipEntity("Invalid Zip64 Extended Information Extra Field")

        result.data_size = struct.unpack("H", buffer[2:4])[0]

        offset = 4
        if fileRecord.file_size == 0xFFFFFFFF:
            result.Set("file_size", struct.unpack("Q", buffer[offset:offset + 8])[0])
            offset += 8

        if fileRecord.compress_size == 0xFFFFFFFF:
            result.Set("compress_size", struct.unpack("Q", buffer[offset:offset + 8])[0])
            offset += 8

        if fileRecord.relative_offset_local_header == 0xFFFFFFFF:
            result.Set("relative_offset_local_header",
                  struct.unpack("Q", buffer[offset:offset + 8])[0])
            offset += 8

        if fileRecord.disk_number_start == 0xFFFF:
            result.Set("disk_number_start", struct.unpack("I", buffer[offset:offset + 4])[0])
            offset += 4

        return (result, offset)


class Zip64EndCD(struct_parser.CreateStruct(
        "Zip64EndCD_t",
        """
        uint32_t magic = 0x06064b50;
        uint64_t size_of_header = 0;
        uint16_t version_made_by = 0x2d;
        uint16_t version_needed = 0x2d;
        uint32_t number_of_disk = 0;
        uint32_t number_of_disk_with_cd = 0;
        uint64_t number_of_entries_in_volume;
        uint64_t total_entries_in_cd;
        uint64_t size_of_cd;
        uint64_t offset_of_cd;
        """)):

    magic_string = b'PK\x06\x06'

    def IsValid(self):
        return self.magic == 0x06064b50

    @classmethod
    def FromBuffer(cls, buffer):
        """Instantiate an EndCentralDirectory from this buffer."""
        # Not enough data to contain an EndCentralDirectory
        if len(buffer) > cls.sizeof():
            # Scan the buffer backwards for an End of Central Directory magic
            end = len(buffer) - cls.sizeof() + 4
            while True:
                index = buffer.rfind(cls.magic_string, 0, end)
                if index < 0:
                    break

                end_cd = cls(buffer[index:])
                if end_cd.IsValid():
                    return end_cd, index

                end = index

        raise IOError("Unable to find EndCentralDirectory")

class Zip64CDLocator(struct_parser.CreateStruct(
        "Zip64CDLocator_t",
        """
        uint32_t magic = 0x07064b50;
        uint32_t disk_with_cd = 0;
        uint64_t offset_of_end_cd;
        uint32_t number_of_disks = 1;
        """)):

    def IsValid(self):
        return (self.magic == 0x07064b50 and
                self.disk_with_cd == 0 and
                self.number_of_disks == 1)


class ZipInfo:
    def __init__(self, compression_method=0, compress_size=0,
                 file_size=0, filename="", local_header_offset=0,
                 crc32=0, lastmoddate=0, lastmodtime=0):
        self.compression_method = compression_method
        self.compress_size = compress_size
        self.file_size = file_size
        self.filename = filename
        self.local_header_offset = local_header_offset
        self.crc32 = crc32
        self.lastmoddate = lastmoddate
        self.lastmodtime = lastmodtime

        self.file_header_offset = None
        # Real file offset of this member's entry in the central directory it was read from.
        self.cd_entry_offset = None

    def WriteFileHeader(self, backing_store):
        if self.file_header_offset is None:
            self.file_header_offset = backing_store.TellWrite()

        encodedFilename = self.filename
        if USE_UNICODE:
            encodedFilename = self.filename.encode("utf-8")

        header = ZipFileHeader(
            crc32=self.crc32,
            compress_size=self.compress_size,
            file_size=self.file_size,
            file_name_length=len(encodedFilename),
            compression_method=self.compression_method,
            lastmodtime=self.lastmodtime,
            lastmoddate=self.lastmoddate,
            extra_field_len=0)

        if USE_UNICODE:
            header.flags = header.flags | (1 << 11)

        # The header is written before the member's data, when its size is not yet known, and
        # rewritten in place afterwards, so it always reserves the Zip64 field: adding it on the
        # rewrite would overwrite the start of the data.
        header.file_size = 0xFFFFFFFF
        header.compress_size = 0xFFFFFFFF
        extra_header_64 = Zip64FileHeaderExtensibleField()
        extra_header_64.Set("file_size", self.file_size)
        extra_header_64.Set("compress_size", self.compress_size)
        header.extra_field_len = extra_header_64.sizeof()

        backing_store.SeekWrite(self.file_header_offset)
        backing_store.Write(header.Pack())
        backing_store.write(encodedFilename)
        backing_store.Write(extra_header_64.Pack())

    def WriteCDFileHeader(self, backing_store):
        encodedFilename = self.filename
        if USE_UNICODE:
            encodedFilename = self.filename.encode("utf-8")
        header = CDFileHeader(
            compression_method=self.compression_method,
            file_size=self.file_size,
            compress_size=self.compress_size,
            relative_offset_local_header=self.local_header_offset,
            crc32=self.crc32,
            file_name_length=len(encodedFilename),
            dostime=self.lastmodtime,
            dosdate=self.lastmoddate)

        if USE_UNICODE:
            header.flags = header.flags | (1 << 11)
        extra_header_64 = Zip64FileHeaderExtensibleField()
        if self.file_size > ZIP32_MAX_SIZE:
            header.file_size = 0xFFFFFFFF
            extra_header_64.Set("file_size", self.file_size)

        if self.compress_size > ZIP32_MAX_SIZE:
            header.compress_size = 0xFFFFFFFF
            extra_header_64.Set("compress_size", self.compress_size)

        if self.local_header_offset > ZIP32_MAX_SIZE:
            header.relative_offset_local_header = 0xFFFFFFFF
            extra_header_64.Set("relative_offset_local_header",
                                self.local_header_offset)

        # Only write the extra header if we have to.
        if not extra_header_64.empty():
            header.extra_field_len = extra_header_64.sizeof()

        backing_store.write(header.Pack())
        backing_store.write(encodedFilename)

        if not extra_header_64.empty():
            backing_store.write(extra_header_64.Pack())


class FileWrapper:
    """Maps a slice from a file URN."""

    def __init__(self, resolver, file_fd, file_urn, slice_offset, slice_size):
        self.file_urn = file_urn
        self.fd = file_fd
        self.resolver = resolver
        self.slice_size = slice_size
        self.slice_offset = slice_offset
        self.readptr = 0

    def seek(self, offset, whence=0):
        if whence == 0:
            self.readptr = offset
        elif whence == 1:
            self.readptr += offset
        elif whence == 2:
            self.readptr = self.slice_size + offset

    def tell(self):
        return self.readptr

    def read(self, length):
        fd = self.fd
        if True:
            fd.seek(self.slice_offset + self.readptr)
            to_read = min(self.slice_size - self.readptr, length)
            result = fd.read(to_read)
            self.readptr += len(result)

            return result

class WritableFileWrapper(FileWrapper):
    """A stored (uncompressed) ZIP member, rewritten in place within its existing size."""

    def write(self, buf):
        # The member's bytes are followed by the next member or the central directory, so a
        # write past its end would overwrite them. Refuse it before writing anything.
        if self.readptr + len(buf) > self.slice_size:
            raise OSError(
                f"Write of {len(buf)} bytes at offset {self.readptr} exceeds the existing ZIP "
                f"segment (size={self.slice_size}); a stored segment can only be rewritten within "
                "its size"
            )
        with self.resolver.AFF4FactoryOpen(self.file_urn) as fd:
            fd.SeekWrite(self.slice_offset + self.readptr, 0)
            fd.write(buf)
            self.readptr += len(buf)
            return len(buf)

    def flush(self):
        pass

def DecompressBuffer(buffer):
    """Decompress using deflate a single buffer.

    We assume the buffer is not too large.
    """
    decompressor = zlib.decompressobj(-15)
    result = decompressor.decompress(buffer, len(buffer))

    return result + decompressor.flush()


class ZipFileSegment(aff4_file.FileBackedObject):
    compression_method = ZIP_STORED

    def __init__(self,  *args, **kwargs):
        super().__init__( *args, **kwargs)
        self.filename = None

    def setCompressionMethod(self, method):
        if method in [ZIP_STORED, lexicon.AFF4_IMAGE_COMPRESSION_STORED]:
            self.compression_method = ZIP_STORED
        elif method == ZIP_DEFLATE:
            self.compression_method = ZIP_DEFLATE
        else:
            raise RuntimeError("Bad compression parameter")

    def LoadFromURN(self):
        owner = self.parent
        if True:
            self.LoadFromZipFile(owner)

    def LoadFromZipFile(self, owner):
        """Read the segment data from the ZipFile owner."""
        # Parse the ZipFileHeader for this filename.
        zip_info = owner.members.get(self.filename)
        self.properties.writable = owner.properties.writable
        if zip_info is None:
            # The owner does not have this file yet - we add it when closing.
            self.fd = io.BytesIO()
            return

        backing_store_urn = owner.backing_store_urn
        backing_store = self.parent.parent
        if True:
            self.local_header_offset = zip_info.local_header_offset + owner.global_offset
            backing_store.SeekRead(0,0)
            backing_store.SeekRead(self.local_header_offset, 0)
            file_header = ZipFileHeader(
                backing_store.Read(ZipFileHeader.sizeof()))
            # Writers that stream a member set the data-descriptor flag and leave the header's CRC
            # zero. pyaff4 sets the flag too but then writes the CRC into the header and no
            # descriptor, so the flag alone does not say where the CRC is.
            self.has_data_descriptor = bool(
                file_header.flags & DATA_DESCRIPTOR_FLAG and file_header.crc32 == 0
                and zip_info.crc32 != 0
            )

            if not file_header.IsValid():
                raise IOError("Local file header invalid!")

            file_header_filename = ""
            if file_header.flags | (1 << 11):
                # decode the filename to UTF-8 if the EFS bit (bit 11) is set
                fn = backing_store.Read(file_header.file_name_length)
                file_header_filename = fn.decode("utf-8")
            else:
                # The filename should be null terminated.
                file_header_filename = backing_store.Read(
                    file_header.file_name_length).split(b"\x00")[0]

            if file_header_filename != zip_info.filename:
                msg = (u"Local filename %s different from "
                       u"central directory %s.") % (
                           file_header_filename, zip_info.filename)
                LOGGER.error(msg)
                raise IOError(msg)

            backing_store.SeekRead(file_header.extra_field_len, aff4.SEEK_CUR)

            buffer_size = zip_info.file_size
            self.size = zip_info.file_size
            if file_header.compression_method == ZIP_DEFLATE:
                # We write the entire file in a memory buffer if we need to
                # deflate it.
                self.compression_method = ZIP_DEFLATE
                c_buffer = backing_store.Read(zip_info.compress_size)
                decomp_buffer = DecompressBuffer(c_buffer)
                if len(decomp_buffer) != buffer_size:
                    LOGGER.info("Unable to decompress file %s", self.urn)
                    raise IOError()

                self.fd = io.BytesIO(decomp_buffer)
                # Writes would only change this decompressed copy: Flush does not store members
                # that already exist, so they would be lost. A compressed member is read-only.
                self.properties.writable = False

            elif file_header.compression_method == ZIP_STORED:
                # Otherwise we map a slice into it.
                if backing_store.properties.writable:
                    self.fd = WritableFileWrapper(self.resolver, backing_store, backing_store_urn,
                                          backing_store.TellRead(), buffer_size)
                else:
                    self.fd = FileWrapper(self.resolver, backing_store, backing_store_urn,
                      backing_store.TellRead(), buffer_size)

            else:
                LOGGER.info("Unsupported compression method.")
                raise NotImplementedError()

    def WriteStream(self, stream, progress=None):
        owner = self.parent
        if True:
            owner.StreamAddSegment(
                self.filename, stream, compression_method=self.compression_method,
                progress=progress)

    def FlushAndClose(self):
        self.Flush()
        self.closed = True

    def Flush(self):
        if self.IsDirty():
            if not self.parent.ContainsSegment(self.filename):
                # only copy into the owner if we dont already exist there
                self.SeekRead(0)

                # Copy ourselves into the owner.
                self.parent.StreamAddSegment(
                    self.filename, self, self.compression_method)
            elif isinstance(self.fd, WritableFileWrapper):
                self._update_stored_crc()

        super().Flush()

    def _update_stored_crc(self):
        """Rewrite the CRC-32 of an existing stored member edited in place.

        The data was rewritten where it lies, so the CRC recorded in the local header, in any
        data descriptor, and in the central directory entry no longer matches it. Each is
        patched where it lies, without moving any other bytes.
        """
        zip_info = self.parent.members[self.filename]
        crc = 0
        wrapper = self.fd
        saved = wrapper.tell()
        wrapper.seek(0)
        while True:
            data = wrapper.read(BUFF_SIZE)
            if not data:
                break
            crc = zlib.crc32(data, crc)
        wrapper.seek(saved)
        crc &= 0xffffffff
        packed = struct.pack("<I", crc)

        with self.resolver.AFF4FactoryOpen(wrapper.file_urn) as backing_store:
            if self.has_data_descriptor:
                # The local header's CRC is zero; the descriptor after the data holds it,
                # optionally preceded by its signature.
                descriptor = wrapper.slice_offset + zip_info.compress_size
                backing_store.SeekRead(descriptor, 0)
                if backing_store.Read(4) == DATA_DESCRIPTOR_SIGNATURE:
                    descriptor += 4
                backing_store.SeekWrite(descriptor, 0)
                backing_store.Write(packed)
            else:
                backing_store.SeekWrite(self.local_header_offset + LOCAL_HEADER_CRC_OFFSET, 0)
                backing_store.Write(packed)
            if zip_info.cd_entry_offset is not None:
                backing_store.SeekWrite(zip_info.cd_entry_offset + CD_ENTRY_CRC_OFFSET, 0)
                backing_store.Write(packed)
        zip_info.crc32 = crc

    def Abort(self):
        if self.IsDirty():
            self._dirty = False
            self.abortSignaled = False
            volume = self.parent
            # make sure that the zip file is marked as dirty
            volume._dirty = True
            volume.RemoveMembers([self.urn])
            self.resolver.DeleteSubject(self.urn)

    def Reset(self):
        self.readptr = 0

    def Close(self):
        pass

    def Size(self):
        return self.size


class BasicZipFile(aff4.AFF4Volume):
    def __init__(self,  *args, **kwargs):
        super().__init__( *args, **kwargs)
        self.arn_in_comment = None
        self.children = set()
        # The members of this zip file. Keys is member URN, value is zip info.
        self.members = {}
        if "prototype" in kwargs:
            self.raw_members = kwargs["prototype"].raw_members
        else:
            self.raw_members = []
        self.global_offset = 0
        try:
            self.version = kwargs["version"]
        except KeyError:
            self.version = Version(0,0, "pyaff4")

        # Derive a stable urn from the backing store. For file-backed zips we
        # use the file:// path under a zip:// scheme so successive opens of
        # the same file produce the same urn. For non-file backings (e.g. an
        # AFF4EncryptedStream backing an inner zip) we keep the urn assigned
        # by AFF4Object's __init__ (either the explicit arn or a generated
        # aff4://uuid) so the inner zip doesn't collide with its backing
        # stream.
        parent_urn_str = self.parent.urn.toPython()
        if parent_urn_str.startswith("file://"):
            self.urn = rdfvalue.ARN(parent_urn_str.replace("file://", "zip://"))

    def __exit__(self, exc_type, exc_value, traceback):
        # Return ourselves to the resolver cache.
        self.resolver.Return(self)
        self.resolver.Return(self.parent)


        # Ensure exceptions aren't silently swallowed (are propagated)
        if exc_value is not None:
            return False


    def parse_cd(self, backing_store_urn):
        backing_store = self.parent
        if True:
            # Find the End of Central Directory Record - We read about 4k of
            # data and scan for the header from the end, just in case there is
            # an archive comment appended to the end.
            segmentMap = {}
            backing_store.SeekRead(-BUFF_SIZE, 2)

            ecd_real_offset = backing_store.TellRead()
            buffer = backing_store.Read(BUFF_SIZE)

            end_cd, buffer_offset = EndCentralDirectory.FromBuffer(buffer)

            urn_string = None

            ecd_real_offset += buffer_offset

            # Fetch the volume comment.
            if end_cd.comment_len > 0:
                backing_store.SeekRead(ecd_real_offset + end_cd.sizeof())
                urn_string = backing_store.Read(end_cd.comment_len).decode("utf-8")

                # trim trailing null if there
                if urn_string[len(urn_string)-1] == chr(0):
                    urn_string = urn_string[0:len(urn_string)-1]
                if LOGGER.isEnabledFor(logging.INFO):
                    LOGGER.info("Loaded AFF4 volume URN %s from zip file.",
                            urn_string)
                self.arn_in_comment = urn_string

            #if end_cd.size_of_cd == 0xFFFFFFFF:
            #    end_cd, buffer_offset = Zip64EndCD.FromBuffer(buffer)



            #LOGGER.info("Found ECD at %#x", ecd_real_offset)



            # There is a catch 22 here - before we parse the ZipFile we dont
            # know the Volume's URN, but we need to know the URN so the
            # AFF4FactoryOpen() can open it. Therefore we start with a random
            # URN and then create a new ZipFile volume. After parsing the
            # central directory we discover our URN and therefore we can delete
            # the old, randomly selected URN.

            directory_offset = end_cd.offset_of_cd
            directory_number_of_entries = end_cd.total_entries_in_cd

            # Traditional zip file - non 64 bit.
            if directory_offset > 0 and directory_offset != 0xffffffff:
                # The global difference between the zip file offsets and real
                # file offsets. This is non zero when the zip file was appended
                # to another file.
                self.global_offset = (
                    # Real ECD offset.
                    ecd_real_offset - end_cd.size_of_cd -

                    # Claimed CD offset.
                    directory_offset)

                if LOGGER.isEnabledFor(logging.INFO):
                    LOGGER.info("Global offset: %#x", self.global_offset)

            # This is a 64 bit archive, find the Zip64EndCD.
            else:
                locator_real_offset = ecd_real_offset - Zip64CDLocator.sizeof()
                backing_store.SeekRead(locator_real_offset, 0)
                locator = Zip64CDLocator(
                    backing_store.Read(Zip64CDLocator.sizeof()))

                if not locator.IsValid():
                    raise IOError("Zip64CDLocator invalid or not supported.")

                # Although it may appear that we can use the Zip64CDLocator to
                # locate the Zip64EndCD record via it's offset_of_cd record this
                # is not quite so. If the zip file was appended to another file,
                # the offset_of_cd field will not be valid, as it still points
                # to the old offset. In this case we also need to know the
                # global shift.
                backing_store.SeekRead(
                    locator_real_offset - Zip64EndCD.sizeof(), 0)

                end_cd = Zip64EndCD(
                    backing_store.Read(Zip64EndCD.sizeof()))

                if not end_cd.IsValid():
                    LOGGER.error("Zip64EndCD magic not correct @%#x",
                                 locator_real_offset - Zip64EndCD.sizeof())
                    raise RuntimeError("Zip64EndCD magic not correct")

                directory_offset = end_cd.offset_of_cd
                directory_number_of_entries = end_cd.number_of_entries_in_volume

                # The global offset is now known:
                self.global_offset = (
                    # Real offset of the central directory.
                    locator_real_offset - Zip64EndCD.sizeof() -
                    end_cd.size_of_cd -

                    # The directory offset in zip file offsets.
                    directory_offset)

                if LOGGER.isEnabledFor(logging.INFO):
                    LOGGER.info("Global offset: %#x", self.global_offset)

            # Now iterate over the directory and read all the ZipInfo structs.
            entry_offset = directory_offset
            backing_store.seek(entry_offset, 0)
            cd_data = backing_store.read(end_cd.size_of_cd)
            backing_store = io.BytesIO(cd_data)
            entry_offset = 0
            for _ in range(directory_number_of_entries):
                backing_store.seek(entry_offset, 0)
                entry = CDFileHeader(
                    backing_store.read(CDFileHeader.sizeof()))

                if not entry.IsValid():
                    if LOGGER.isEnabledFor(logging.INFO):
                        LOGGER.info("CDFileHeader at offset %#x invalid", entry_offset)
                    raise RuntimeError()

                fn = backing_store.read(entry.file_name_length)

                # decode the filename to UTF-8 if the EFS bit (bit 11) is set
                if entry.flags | (1 << 11):
                    fn = fn.decode("utf-8")

                zip_info = ZipInfo(
                    filename=fn,
                    local_header_offset=entry.relative_offset_local_header,
                    compression_method=entry.compression_method,
                    compress_size=entry.compress_size,
                    file_size=entry.file_size,
                    crc32=entry.crc32,
                    lastmoddate=entry.dosdate,
                    lastmodtime=entry.dostime)

                # Zip64 local header - parse the Zip64 extended information extra field.
                # if zip_info.local_header_offset < 0 or zip_info.local_header_offset == 0xffffffff:
                if entry.extra_field_len > 0:
                    extrabuf = backing_store.read(entry.extra_field_len)

                    # AFF4 requres Zip64, but we still want to be able to read 3rd party
                    # zip files, so just skip unknown Extensible data fields and find the Zip64

                    while len(extrabuf) > 0:
                        (headerID, dataSize) = struct.unpack("<HH", extrabuf[0:4])
                        if headerID == 1:
                            # Zip64 extended information extra field
                            extra, readbytes = Zip64FileHeaderExtensibleField.FromBuffer(
                                entry, extrabuf)
                            extrabuf = extrabuf[readbytes:]

                            if extra.header_id == 1:
                                if extra.Get("relative_offset_local_header") is not None:
                                    zip_info.local_header_offset = (
                                        extra.Get("relative_offset_local_header"))
                                if extra.Get("file_size") is not None:
                                    zip_info.file_size = extra.Get("file_size")
                                if extra.Get("compress_size") is not None:
                                    zip_info.compress_size = extra.Get("compress_size")
                        else:
                            extrabuf = extrabuf[dataSize + 4:]


                if LOGGER.isEnabledFor(logging.INFO):
                    LOGGER.info("Found file %s @ %#x", zip_info.filename,
                            zip_info.local_header_offset)

                zip_info.cd_entry_offset = directory_offset + self.global_offset + entry_offset

                # Store this information in the resolver. Ths allows
                # segments to be directly opened by URN.
                self.members[zip_info.filename] = zip_info
                self.raw_members.append(zip_info)


                # Go to the next entry.
                entry_offset += (entry.sizeof() +
                                 entry.file_name_length +
                                 entry.extra_field_len +
                                 entry.file_comment_length)
                segmentMap[zip_info.filename] = zip_info

        self.resolver.segmentCache[self.urn] = (segmentMap, self.version)

    def initialize_from_zipinfos(self, zip_infos):
        for zip_info in zip_infos:
            # Store this information in the resolver. Ths allows
            # segments to be directly opened by URN.

            member_urn = escaping.urn_from_member_name(
                zip_info.filename, self.urn, self.version)

            self.resolver.Set(lexicon.transient_graph,
                              member_urn, lexicon.AFF4_TYPE, lexicon.AFF4_ZIP_SEGMENT_TYPE)

            self.resolver.Set(lexicon.transient_graph, member_urn, lexicon.AFF4_STORED, self.urn)
            self.resolver.Set(lexicon.transient_graph, member_urn, lexicon.AFF4_STREAM_SIZE,
                              Literal(zip_info.file_size, datatype=XSD.long))
            self.members[member_urn] = zip_info

    @staticmethod
    def NewZipFile(resolver, vers, backing_store_urn, zip_members=None, appendmode=None, arn=None):
        rdfvalue.AssertURN(backing_store_urn)
        # If the backing store is already an open stream in the cache (e.g. an
        # AFF4EncryptedStream backing an inner zip), use it directly. This
        # supports nested-volume scenarios where the zip is backed by an AFF4
        # stream rather than a plain file.
        backing_file = resolver.ObjectCache.Get(backing_store_urn)
        if backing_file is None:
            backing_file = FileBackedObject(resolver, backing_store_urn, None, appendmode=appendmode)
            backing_file.LoadFromURN()
            resolver.ObjectCache.Put(backing_file, True)
        backing_file.Prepare()
        mode = None
        if vers is None:
            vers = Version(0,1,"pyaff4")

        if appendmode is not None and appendmode != "w":
            mode = "append"
        result = ZipFile(resolver, arn, backing_file, version=vers, appendmode = mode)
        result.LoadFromURN()
        resolver.ObjectCache.Put(result, True)
        result.Prepare()
        return result

    # def ContainsMember(self, arn):
    #     #for member in self.members:
    #     #    if member == arn:
    #     #        return True
    #     if arn in self.members:
    #         return True
    #     return False

    def ContainsSegment(self, segment_name):
        #segment_arn = escaping.urn_from_member_name(segment_name, self.urn, self.version)
        #for member in self.members:
        #    if member == arn:
        #        return True
        if segment_name in self.members:
            return True
        return False

    def CreateMember(self, child_urn):
        member_filename = escaping.member_name_for_urn(child_urn, self.version, self.urn, use_unicode=USE_UNICODE)
        return self.CreateZipSegment(member_filename, arn=child_urn)


    def CreateZipSegment(self, filename, arn=None):
        if not self.properties.writable:
            raise IOError("Appempt to create Zip Segment in R/O Object")
        self.MarkDirty()
        segment_urn = arn
        if arn is None:
            segment_urn = escaping.urn_from_member_name(filename, self.urn, self.version)

        # Is it in the cache?
        res = self.resolver.CacheGet(segment_urn)
        if res is not None:
            res.readptr = 0
            return res

        #  Keep track of all the segments we issue.
        self.children.add(segment_urn)

        result = ZipFileSegment(self.resolver, segment_urn, self)
        result.filename = filename
        # LoadFromZipFile decides writability: a new member or a stored one (rewritten in place)
        # is writable; an existing compressed member is not, since Flush would drop the writes.
        # Remove such a member first to replace it.
        result.LoadFromZipFile(self)

        LOGGER.info(u"Creating ZipFileSegment %s",
                    result.urn.toPython())

        # Add the new object to the object cache.
        return self.resolver.CachePut(result)

    def OpenZipSegment(self, filename):
        # Is it already in the cache?
        segment_urn = escaping.urn_from_member_name(filename, self.urn, self.version)

        if filename not in self.members:
            raise IOError("Segment %s does not exist yet" % filename)

        res = self.resolver.CacheGet(segment_urn)

        if res:
            if LOGGER.isEnabledFor(logging.INFO):
                LOGGER.info("Openning ZipFileSegment (cached) %s", res.urn)
            res.Reset()
            return res

        self.children.add(segment_urn)

        result = ZipFileSegment(self.resolver, segment_urn, self)
        result.filename = filename
        result.LoadFromZipFile(self)

        if LOGGER.isEnabledFor(logging.INFO):
            LOGGER.info("Opening ZipFileSegment %s", result.urn)

        return self.resolver.CachePut(result)

    def OpenMember(self, segment_urn):
        # Is it already in the cache?
        filename = escaping.member_name_for_urn(segment_urn, self.version, self.urn)
        if segment_urn not in self.members:
            raise IOError("Segment %s does not exist yet" % segment_urn)

        res = self.resolver.CacheGet(segment_urn)

        if res:
            if LOGGER.isEnabledFor(logging.INFO):
                LOGGER.info("Openning ZipFileSegment (cached) %s", res.urn)
            res.Reset()
            return res

        self.children.add(segment_urn)

        result = ZipFileSegment(self.resolver, segment_urn, self)
        result.LoadFromZipFile(owner=self)

        if LOGGER.isEnabledFor(logging.INFO):
            LOGGER.info("Opening ZipFileSegment %s", result.urn)

        return self.resolver.CachePut(result)



    def LoadFromURN(self):
        self.backing_store_urn = self.parent.urn
        appendMode = getattr(self.parent, 'mode', None)
        if str(appendMode) in ["truncate", "append", "random" ]:
            self.properties.writable = True
        elif self.parent.properties.writable:
            # The backing stream (e.g. an AFF4EncryptedStream) reports
            # writability directly rather than via a 'mode' attribute.
            self.properties.writable = True

        try:
            if len(self.raw_members) > 0:
                self.initialize_from_zipinfos(self.raw_members)
            else:
                self.parse_cd(self.backing_store_urn)
        except IOError:
            # If we can not parse a CD from the zip file, this is fine, we just
            # append an AFF4 volume to it, or make a new file.
            return



    def StreamAddSegment(self, segment_name, stream,
                        compression_method=ZIP_STORED,
                        progress=None):
        """An efficient interface to add a new archive member.

        Args:
          member_urn: The new member URN to be added.
          stream: A file-like object (with read() method) that generates data to
            be written as the member.
          compression_method: How to compress the member.

        """
        if compression_method not in (ZIP_DEFLATE, ZIP_STORED):
            raise RuntimeError(
                f"Unsupported compression method {compression_method!r} for {segment_name}")
        if progress is None:
            progress = aff4.EMPTY_PROGRESS

        backing_store = self.parent
        if True:
            # Append member at the end of the file.
            backing_store.SeekWrite(0, aff4.SEEK_END)

            if LOGGER.isEnabledFor(logging.INFO):
                LOGGER.info("Appending ZIP file header %s @ %x", segment_name, backing_store.TellWrite())

            # zip_info offsets are relative to the start of the zip file (take
            # global_offset into account).
            zip_info = ZipInfo(
                local_header_offset=backing_store.TellWrite() - self.global_offset,
                filename=segment_name,
                file_size=0, crc32=0, compression_method=compression_method)

            # For now we do not support streamed writing so we need to seek back
            # to this position later with an updated crc32.
            zip_info.WriteFileHeader(backing_store)

            start_of_stream_addr = backing_store.TellWrite()

            if compression_method == ZIP_DEFLATE:
                zip_info.compression_method = ZIP_DEFLATE
                compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION,
                                              zlib.DEFLATED, -15)
                while True:
                    try:
                        data = stream.read(BUFF_SIZE)
                        if not data:
                            break
                    except IOError:
                        break

                    c_data = compressor.compress(data)
                    zip_info.compress_size += len(c_data)
                    zip_info.file_size += len(data)
                    # Python 2 erronously returns a signed int here.
                    zip_info.crc32 = zlib.crc32(data, zip_info.crc32) & 0xffffffff
                    if len(c_data) > 0:
                        backing_store.Write(c_data)
                    progress.Report(zip_info.file_size)

                # Finalize the compressor.
                c_data = compressor.flush()
                zip_info.compress_size += len(c_data)
                backing_store.Write(c_data)

            # Just write the data directly.
            elif compression_method == ZIP_STORED:
                zip_info.compression_method = ZIP_STORED
                while True:
                    data = stream.read(BUFF_SIZE)
                    if not data:
                        break

                    zip_info.compress_size += len(data)
                    zip_info.file_size += len(data)
                    # Python 2 erronously returns a signed int here.
                    zip_info.crc32 = zlib.crc32(data, zip_info.crc32) & 0xffffffff
                    progress.Report(zip_info.file_size)
                    backing_store.Write(data)

            if LOGGER.isEnabledFor(logging.INFO):
                LOGGER.info("Wrote ZIP stream @ %x[%x]", start_of_stream_addr, zip_info.compress_size)

            # Update the local file header now that CRC32 is calculated.
            if LOGGER.isEnabledFor(logging.INFO):
                LOGGER.info("Updating ZIP file header %s @ %x", segment_name, zip_info.file_header_offset)
            zip_info.WriteFileHeader(backing_store)
            self.members[segment_name] = zip_info

    def RemoveMember(self, child_urn):
        self.RemoveMembers([child_urn])

    def RemoveMembers(self, child_urns):
        trimStorage = True
        backing_store = self.parent
        if True:
            try:
                for zip_info in sorted(list(self.members.values()),
                                       key=lambda k: 0 if k.file_header_offset is None else k.file_header_offset,
                                       reverse=True):
                    arn = escaping.urn_from_member_name(zip_info.filename, self.urn, self.version)
                    if arn in child_urns:
                        # The segment may have been cached under the
                        # zip-scheme arn computed above OR an aff4-scheme arn
                        # if it was created via ZipMemberContainer.CreateMember
                        # or opened via the containerMap path in
                        # AFF4FactoryOpen. Walk the cache to find every cached
                        # ZipFileSegment whose filename matches and drop it,
                        # otherwise a subsequent CreateMember will hand back
                        # the stale instance with its WritableFileWrapper fd.
                        cache = self.resolver.ObjectCache
                        all_entries = (list(cache.in_use.values())
                                       + list(cache.lru_map.values()))
                        for entry in all_entries:
                            obj = entry.aff4_obj
                            if getattr(obj, 'filename', None) == zip_info.filename \
                                    and getattr(obj, 'parent', None) is self:
                                # Mark the cached segment clean to avoid Flush
                                # re-adding it via StreamAddSegment when the
                                # cache evicts it.
                                obj._dirty = False
                                cache.Remove(obj)

                        # Drop any matching child arn (regardless of scheme).
                        for child_arn in list(self.children):
                            if not isinstance(child_arn, URIRef):
                                # Tolerate raw-filename entries that may have
                                # been added by older code paths.
                                if child_arn == zip_info.filename:
                                    self.children.remove(child_arn)
                                continue
                            child_filename = escaping.member_name_for_urn(
                                child_arn, self.version, self.urn,
                                use_unicode=USE_UNICODE)
                            if child_filename == zip_info.filename:
                                self.children.remove(child_arn)

                        if self.members[zip_info.filename] is not None:
                            del self.members[zip_info.filename]

                        if trimStorage:
                            backing_store.Trim(zip_info.file_header_offset)
                    else:
                        trimStorage = False
            except Exception:
                for arn in child_urns:
                    if self.resolver.CacheContains(arn):
                        obj = self.resolver.CacheGet(arn)
                        self.resolver.ObjectCache.Remove(obj)

                    if arn in self.children:
                        self.children.remove(arn)
                    if arn in self.members:
                        del self.members[arn]


    def RemoveSegment(self, segment_name):
        segment_arn = escaping.urn_from_member_name(segment_name, self.urn, self.version)
        self.RemoveMember(segment_arn)

    def Flush(self):

        # If the zip file was changed, re-write the central directory.
        if self.IsDirty():
            # Flush any dirty cached object whose parent chain lands on this
            # zip — that includes AFF4Maps, AFF4Images, and ZipFileSegments
            # whose contents must be written into self.members before we
            # finalise the central directory. Repeat until quiescent: a flush
            # may add more children (e.g. an AFF4Image creating bevy
            # segments).
            cache = self.resolver.ObjectCache
            while True:
                flushed_one = False
                entries = list(cache.in_use.values()) + list(cache.lru_map.values())
                for entry in entries:
                    obj = entry.aff4_obj
                    if obj is self or not obj.IsDirty():
                        continue
                    p = getattr(obj, 'parent', None)
                    backs_us = False
                    while p is not None:
                        if p is self:
                            backs_us = True
                            break
                        p = getattr(p, 'parent', None)
                    if not backs_us:
                        continue
                    if getattr(obj, 'filename', None) == "information.turtle":
                        # We don't re-flush an existing information.turtle —
                        # DumpToTurtle handles re-emission below.
                        continue
                    obj.Flush()
                    flushed_one = True
                if not flushed_one:
                    break

            # above; clear the residual entries so subsequent flushes don't
            # re-process them.
            self.children.clear()

            # Add the turtle and HDT metadata to the volume.
            self.resolver.DumpToTurtle(self)
            self.resolver.DumpToHdt(self)

            # Write the central directory.
            self.write_zip64_CD()

        super().Flush()

    def write_zip64_CD(self):
        backing_store = self.parent
        if True:
            # We write to a memory stream first, and then copy it into the
            # backing_store at once. This really helps when we have lots of
            # members in the zip archive.
            cd_stream = io.BytesIO()

            # Append a new central directory to the end of the zip file.
            backing_store.SeekWrite(0, aff4.SEEK_END)

            # The real start of the ECD.
            ecd_real_offset = backing_store.TellWrite()

            total_entries = len(self.members)
            for urn, zip_info in list(self.members.items()):
                if LOGGER.isEnabledFor(logging.INFO):
                    LOGGER.info("Writing CD entry for %s", urn)
                zip_info.WriteCDFileHeader(cd_stream)

            offset_of_end_cd = cd_stream.tell() + ecd_real_offset - self.global_offset
            size_of_cd = cd_stream.tell()
            offset_of_cd = offset_of_end_cd - size_of_cd
            #urn_string = self.urn.toPython()
            urn_string = self.arn_in_comment
            comment_len = 0
            if urn_string is not None:
                comment_len = len(urn_string)

            # the following is included for debugging the zip implementation.
            # for small zip files, enable output to non-zip64 containers
            # NOT TO BE USED IN PRODUCTION
            if not ZIP_DEBUG or offset_of_cd > ZIP32_MAX_SIZE or size_of_cd > ZIP32_MAX_SIZE or total_entries > 0xffff:
                # only write zip64 headers if needed
                locator = Zip64CDLocator(
                    offset_of_end_cd=(offset_of_end_cd))

                end_cd = Zip64EndCD(
                    size_of_header=Zip64EndCD.sizeof()-12,
                    number_of_entries_in_volume=total_entries,
                    total_entries_in_cd=total_entries,
                    size_of_cd=size_of_cd,
                    offset_of_cd=offset_of_cd)

                if LOGGER.isEnabledFor(logging.INFO):
                    LOGGER.info("Writing Zip64EndCD at %#x",
                            cd_stream.tell() + ecd_real_offset)
                cd_stream.write(end_cd.Pack())
                cd_stream.write(locator.Pack())

            end = EndCentralDirectory(
                total_entries_in_cd_on_disk=total_entries,
                total_entries_in_cd=total_entries,
                comment_len=comment_len,
                offset_of_cd = offset_of_cd,
                size_of_cd = size_of_cd)

            if size_of_cd > ZIP32_MAX_SIZE or not ZIP_DEBUG :
                end.size_of_cd = 0xffffffff

            if offset_of_end_cd > ZIP32_MAX_SIZE or not ZIP_DEBUG :
                end.offset_of_cd = 0xffffffff

            if total_entries > 0xffff:
                end.total_entries_in_cd_on_disk = 0xffff
                end.total_entries_in_cd = 0xffff

            if LOGGER.isEnabledFor(logging.INFO):
                LOGGER.info("Writing ECD at %#x",
                        cd_stream.tell() + ecd_real_offset)

            cd_stream.write(end.Pack())
            if comment_len > 0:
                cd_stream.write(urn_string.encode("utf-8"))

            # Now copy the cd_stream into the backing_store in one write
            # operation.
            backing_store.write(cd_stream.getvalue())

    def Close(self):
        pass

class ZipFile(BasicZipFile):
    def __init__(self,  *args, **kwargs):
        super().__init__( *args, **kwargs)

    def LoadFromURN(self):
        super().LoadFromURN()
        if len(self.members) == 0:
            return
        # Load the turtle metadata.

registry.AFF4_TYPE_MAP[lexicon.AFF4_ZIP_TYPE] = ZipFile
registry.AFF4_TYPE_MAP[lexicon.AFF4_ZIP_SEGMENT_TYPE] = ZipFileSegment
registry.AFF4_TYPE_MAP["StandardZip"] = BasicZipFile
