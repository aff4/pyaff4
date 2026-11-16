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

"""The AFF4 lexicon."""
# This is the version of the AFF4 specification we support - not the library
# version itself.

import rdflib
from rdflib import URIRef

from pyaff4 import rdfvalue

AFF4_VERSION = "0.2"

AFF4_MAX_READ_LEN = 1024*1024*100

AFF4_NAMESPACE = "http://aff4.org/Schema#"
AFF4_LEGACY_NAMESPACE = "http://afflib.org/2009/aff4#"
XSD_NAMESPACE = "http://www.w3.org/2001/XMLSchema#"
RDF_NAMESPACE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
AFF4_MEMORY_NAMESPACE = "http://aff4.org/Schema#memory/"
AFF4_DISK_NAMESPACE = "http://aff4.org/Schema#disk/"
AFF4_MACOS_NAMESPACE = "http://aff4.org/Schema#macos/"

# Attributes in this namespace will never be written to persistant
# storage. They are simply used as a way for storing metadata about an AFF4
# object internally.
AFF4_VOLATILE_NAMESPACE = "http://aff4.org/VolatileSchema#"

# The configuration space of the library itself. All these should be volatile
# and therefore not persistant or interoperable with other AFF4 implementations.
AFF4_CONFIG_NAMESPACE = AFF4_NAMESPACE + "config"

# Location of the cache (contains AFF4_FILE_NAME)
AFF4_CONFIG_CACHE_DIR = AFF4_CONFIG_NAMESPACE + "/cache"


# Commonly used RDF types.
URNType = "URN"
XSDStringType = (XSD_NAMESPACE + "string")
RDFBytesType = (XSD_NAMESPACE + "hexBinary")
XSDIntegerType = (XSD_NAMESPACE + "integer")
XSDIntegerTypeInt = (XSD_NAMESPACE + "int")
XSDIntegerTypeLong = (XSD_NAMESPACE + "long")
XSDBooleanType = (XSD_NAMESPACE + "boolean")

# Attribute names for different AFF4 objects.
# Base AFF4Object
AFF4_TYPE = URIRef(RDF_NAMESPACE + "type")
AFF4_STORED = URIRef(AFF4_NAMESPACE + "stored")
AFF4_CONTAINS = URIRef(AFF4_NAMESPACE + "contains")

# Each container should have this file which contains the URN of the container.
AFF4_CONTAINER_DESCRIPTION = "container.description"
AFF4_CONTAINER_INFO_TURTLE = "information.turtle"
AFF4_CONTAINER_INFO_YAML = "information.yaml"

# AFF4 ZipFile containers.
AFF4_ZIP_TYPE = URIRef(AFF4_NAMESPACE + "zip_volume")

# AFF4Stream
AFF4_STREAM_SIZE = URIRef(AFF4_NAMESPACE + "size")
AFF4_LEGACY_STREAM_SIZE = URIRef(AFF4_LEGACY_NAMESPACE + "size")

# Can be "read", "truncate", "append"
AFF4_STREAM_WRITE_MODE = URIRef(AFF4_VOLATILE_NAMESPACE + "writable")

# FileBackedObjects are either marked explicitly or using the file:// scheme.
AFF4_FILE_TYPE = URIRef(AFF4_NAMESPACE + "file")

# file:// based URNs do not always have a direct mapping to filesystem
# paths. This volatile attribute is used to control the filename mapping.
AFF4_FILE_NAME = URIRef(AFF4_VOLATILE_NAMESPACE + "filename")

# The original filename the stream had.
AFF4_STREAM_ORIGINAL_FILENAME = URIRef(AFF4_NAMESPACE + "original_filename")

# ZipFileSegment
AFF4_ZIP_SEGMENT_TYPE = URIRef(AFF4_NAMESPACE + "zip_segment")

# ZipStoredLogicalStream
AFF4_ZIP_SEGMENT_IMAGE_TYPE = URIRef(AFF4_NAMESPACE + "ZipSegment")
AFF4_FILEIMAGE = URIRef(AFF4_NAMESPACE + "FileImage")

# AFF4 Image Stream - stores a stream using Bevies.
AFF4_IMAGE_TYPE = URIRef(AFF4_NAMESPACE + "ImageStream")
AFF4_LEGACY_IMAGE_TYPE = URIRef(AFF4_LEGACY_NAMESPACE + "stream")
AFF4_SCUDETTE_IMAGE_TYPE = URIRef(AFF4_NAMESPACE + "image")
AFF4_IMAGE_CHUNK_SIZE = URIRef(AFF4_NAMESPACE + "chunkSize")
AFF4_LEGACY_IMAGE_CHUNK_SIZE = URIRef(AFF4_LEGACY_NAMESPACE + "chunkSize")
AFF4_IMAGE_CHUNKS_PER_SEGMENT = URIRef(AFF4_NAMESPACE + "chunksInSegment")
AFF4_LEGACY_IMAGE_CHUNKS_PER_SEGMENT = URIRef(AFF4_LEGACY_NAMESPACE + "chunksInSegment")
AFF4_IMAGE_COMPRESSION = URIRef(AFF4_NAMESPACE + "compressionMethod")
AFF4_LEGACY_IMAGE_COMPRESSION = URIRef(AFF4_LEGACY_NAMESPACE + "CompressionMethod")
AFF4_IMAGE_COMPRESSION_ZLIB = URIRef("https://www.ietf.org/rfc/rfc1950.txt")
AFF4_IMAGE_COMPRESSION_SNAPPY = URIRef("http://code.google.com/p/snappy/")
AFF4_IMAGE_COMPRESSION_SNAPPY_SCUDETTE = URIRef("https://github.com/google/snappy")
AFF4_IMAGE_COMPRESSION_LZ4 = URIRef("https://code.google.com/p/lz4/")
AFF4_IMAGE_COMPRESSION_STORED = URIRef(AFF4_NAMESPACE + "compression/stored")
AFF4_IMAGE_COMPRESSION_NONE = URIRef(AFF4_NAMESPACE + "NullCompressor")
AFF4_IMAGE_AES_XTS = URIRef("https://doi.org/10.1109/IEEESTD.2008.4493450")

# AFF4Map - stores a mapping from one stream to another.
AFF4_MAP_TYPE = URIRef(AFF4_NAMESPACE + "Map")
AFF4_LEGACY_MAP_TYPE = URIRef(AFF4_LEGACY_NAMESPACE + "map")
AFF4_SCUDETTE_MAP_TYPE = URIRef(AFF4_NAMESPACE + "map")

# Encrypted Streams
AFF4_ENCRYPTEDSTREAM_TYPE = URIRef(AFF4_NAMESPACE + "EncryptedStream")
AFF4_RANDOMSTREAM_TYPE = URIRef(AFF4_NAMESPACE + "RandomAccessImageStream")
AFF4_KEYBAG = URIRef(AFF4_NAMESPACE + "keyBag")
AFF4_WRAPPEDKEY = URIRef(AFF4_NAMESPACE + "wrappedKey")
AFF4_SALT = URIRef(AFF4_NAMESPACE + "salt")
AFF4_ITERATIONS = URIRef(AFF4_NAMESPACE + "iterations")
AFF4_KEYSIZEBYTES = URIRef(AFF4_NAMESPACE + "keySizeInBytes")
AFF4_CERT_ENCRYPTED_KEYBAG = URIRef(AFF4_NAMESPACE + "PublicKeyEncryptedKeyBag")
AFF4_PASSWORD_WRAPPED_KEYBAG = URIRef(AFF4_NAMESPACE + "PasswordWrappedKeyBag")
AFF4_SERIALNUMBER = URIRef(AFF4_NAMESPACE + "serialNumber")
AFF4_SUBJECTNAME = URIRef(AFF4_NAMESPACE + "x509SubjectName")


# Categories describe the general type of an image.
AFF4_CATEGORY = (AFF4_NAMESPACE + "category")

# These represent standard attributes to describe memory forensics images.
AFF4_MEMORY_PHYSICAL = (AFF4_MEMORY_NAMESPACE + "physical")
AFF4_MEMORY_VIRTUAL = (AFF4_MEMORY_NAMESPACE + "virtual")
AFF4_MEMORY_PAGEFILE = (AFF4_MEMORY_NAMESPACE + "pagefile")
AFF4_MEMORY_PAGEFILE_NUM = (AFF4_MEMORY_NAMESPACE + "pagefile_number")

AFF4_DISK_RAW = (AFF4_DISK_NAMESPACE + "raw")
AFF4_DISK_PARTITION = (AFF4_DISK_NAMESPACE + "partition")

AFF4_DIRECTORY_TYPE = URIRef(AFF4_NAMESPACE + "directory")

#The constant stream is a psuedo stream which just returns a constant.
AFF4_CONSTANT_TYPE = (AFF4_NAMESPACE + "constant")

# The constant to repeat (default 0).
AFF4_CONSTANT_CHAR = (AFF4_NAMESPACE + "constant_char")


# An AFF4 Directory stores all members as files on the filesystem. Some
# filesystems can not represent the URNs properly, hence we need a mapping
# between the URN and the filename. This attribute stores the _relative_ path
# of the filename for the member URN relative to the container's path.
AFF4_DIRECTORY_CHILD_FILENAME = URIRef(AFF4_NAMESPACE + "directory/filename")

HASH_SHA512 = rdflib.URIRef("http://aff4.org/Schema#SHA512")
HASH_SHA256 = rdflib.URIRef("http://aff4.org/Schema#SHA256")
HASH_SHA1 = rdflib.URIRef("http://aff4.org/Schema#SHA1")
HASH_MD5 = rdflib.URIRef("http://aff4.org/Schema#MD5")
HASH_BLAKE2B = rdflib.URIRef("http://aff4.org/Schema#Blake2b")

HASH_BLOCKMAPHASH_SHA512 = rdflib.URIRef("http://aff4.org/Schema#blockMapHashSHA512")

class Lexicon:
    def __init__(self):
        pass

    def of(self, end):
        return URIRef(self.base + end)

class StdLexicon(Lexicon):
    base = AFF4_NAMESPACE
    map = rdflib.URIRef(base + "Map")
    Image = rdflib.URIRef(base + "Image")
    stored = rdflib.URIRef(base + "stored")
    target = rdflib.URIRef(base + "target")
    contains = rdflib.URIRef(base + "contains")
    dataStream = rdflib.URIRef(base + "dataStream")
    blockMapHash = rdflib.URIRef(base + "blockMapHash")
    dependentStream = rdflib.URIRef(base + "dependentStream")
    mapPointHash = rdflib.URIRef(base + "mapPointHash")
    mapIdxHash = rdflib.URIRef(base + "mapIdxHash")
    mapPathHash = rdflib.URIRef(base + "mapPathHash")
    blockHashesHash = rdflib.URIRef(base + "blockHashesHash")
    mapHash = rdflib.URIRef(base + "mapHash")
    imageStreamHash = rdflib.URIRef(base + "imageStreamHash")
    imageStreamIndexHash = rdflib.URIRef(base + "imageStreamIndexHash")
    hash = rdflib.URIRef(base + "hash")
    chunksPerSegment = rdflib.URIRef(base + "chunksInSegment")
    chunkSize = rdflib.URIRef(base + "chunkSize")
    streamSize = rdflib.URIRef(base + "size")
    compressionMethod = rdflib.URIRef(base + "compressionMethod")
    memoryPageTableEntryOffset = rdflib.URIRef(base + "memoryPageTableEntryOffset")
    ntKernelBase = rdflib.URIRef(base + "NTKernelBase")
    OSXKernelPhysicalOffset = rdflib.URIRef(base + "OSXKernelPhysicalOffset")
    OSXKALSRSlide = rdflib.URIRef(base + "OSXKALSRSlide")
    OSXDTBPhysicalOffset = rdflib.URIRef(base + "OSXDTBPhysicalOffset")
    zeroStream = rdflib.URIRef(base + "Zero")
    unknownDataStream = rdflib.URIRef(base + "UnknownData")
    unreadableDataStream = rdflib.URIRef(base + "UnreadableData")

class Std11Lexicon(StdLexicon):
    base = AFF4_NAMESPACE
    FileImage = rdflib.URIRef(base + "FileImage")
    FolderImage = rdflib.URIRef(base + "Folder")
    lastWritten = rdflib.URIRef(base+ "lastWritten")
    lastAccessed = rdflib.URIRef(base + "lastAccessed")
    recordChanged = rdflib.URIRef(base + "recordChanged")
    birthTime = rdflib.URIRef(base + "birthTime")
    pathName = rdflib.URIRef(base + "originalFileName")
    fileName = rdflib.URIRef(base + "fileName")
    fileMode = rdflib.URIRef(base + "fileMode")
    symlinkTarget = rdflib.URIRef(base + "symlinkTarget")
    collidingDataStream = rdflib.URIRef(base + "collidingDataStream")
    child = rdflib.URIRef(base + "child")
    LogicalAcquisitionTask = rdflib.URIRef(base + "LogicalAcquisitionTask")
    filesystemRoot   = rdflib.URIRef(base + "filesystemRoot")
    keyBag = rdflib.URIRef(AFF4_KEYBAG)
    salt = rdflib.URIRef(AFF4_SALT)
    iterations = rdflib.URIRef(AFF4_ITERATIONS)
    keySizeInBytes = rdflib.URIRef(AFF4_KEYSIZEBYTES)
    wrappedKey = rdflib.URIRef(AFF4_WRAPPEDKEY)
    EncryptedStream = rdflib.URIRef(AFF4_ENCRYPTEDSTREAM_TYPE)
    CertEncryptedKeyBag =  rdflib.URIRef(AFF4_CERT_ENCRYPTED_KEYBAG)
    PasswordWrappedKeyBag = rdflib.URIRef(AFF4_PASSWORD_WRAPPED_KEYBAG)
    serialNumber = rdflib.URIRef(AFF4_SERIALNUMBER)
    subjectName = rdflib.URIRef(AFF4_SUBJECTNAME)

# AFF4-L v1.1 containers written by tools other than pyaff4
# record the file path as aff4:originalPathName rather than aff4:originalFileName
class InterimAff4lLexicon(Std11Lexicon):
    pathName = rdflib.URIRef(Std11Lexicon.base + "originalPathName")


class LegacyLexicon(Lexicon):
    base = AFF4_LEGACY_NAMESPACE
    map = rdflib.URIRef(base + "map")
    stored = rdflib.URIRef(base + "stored")
    Image = rdflib.URIRef(base + "Image")
    blockHashesHash = rdflib.URIRef(base + "blockHashesHash")
    mapPointHash = rdflib.URIRef(base + "mapPointHash")
    mapIdxHash = rdflib.URIRef(base + "mapIdxHash")
    mapPathHash = rdflib.URIRef(base + "mapPathHash")
    mapHash = rdflib.URIRef(base + "mapHash")
    hash = rdflib.URIRef(base + "hash")
    chunksPerSegment = rdflib.URIRef(base + "chunksInSegment")
    chunkSize = rdflib.URIRef(base + "chunkSize")
    streamSize = rdflib.URIRef(base + "size")
    compressionMethod = rdflib.URIRef(base + "CompressionMethod")
    zeroStream = rdflib.URIRef(base + "Zero")
    ffStream = rdflib.URIRef(base + "FF")
    unknownDataStream = rdflib.URIRef(base + "UnknownData")

class ScudetteLexicon(Lexicon):
    base = AFF4_NAMESPACE
    map = rdflib.URIRef(base + "map")
    stored = rdflib.URIRef(base + "stored")
    Image = rdflib.URIRef(base + "Image")
    blockHashesHash = rdflib.URIRef(base + "blockHashesHash")
    mapPointHash = rdflib.URIRef(base + "mapPointHash")
    mapIdxHash = rdflib.URIRef(base + "mapIdxHash")
    mapPathHash = rdflib.URIRef(base + "mapPathHash")
    mapHash = rdflib.URIRef(base + "mapHash")
    hash = rdflib.URIRef(base + "hash")
    chunksPerSegment = rdflib.URIRef(base + "chunks_per_segment")
    chunkSize = rdflib.URIRef(base + "chunk_size")
    streamSize = rdflib.URIRef(base + "size")
    compressionMethod = rdflib.URIRef(base + "compression")
    category  = rdflib.URIRef(base + "category")
    memoryPhysical = rdflib.URIRef("http://aff4.org/Schema#memory/physical")
    zeroStream = rdflib.URIRef(base + "Zero")

# early logical imaging support for pmem
class PmemLogicalPreStd(StdLexicon):
    pathName = (AFF4_NAMESPACE + "original_filename")


legacy = LegacyLexicon()
standard = StdLexicon()
scudette = ScudetteLexicon()
standard11 = Std11Lexicon()
interimAff4l = InterimAff4lLexicon()
pmemlogical = PmemLogicalPreStd()

def AutoResolveAttribute(resolver, urn, attribute):
    """Iterate over all lexicons to autodetect the attribute."""
    for lexicon in (standard, scudette, legacy):
        result = resolver.Get(urn, getattr(lexicon, attribute))
        if result is not None:
            return result

transient_graph = rdflib.URIRef("http://aff4.org/Schema#transient")
any = rdflib.URIRef("http://aff4.org/Schema#any")