from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals
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

from builtins import next
from builtins import str
from builtins import object

from pyaff4.utils import SmartStr, SmartUnicode
from pyaff4 import data_store, aff4_image
from pyaff4 import hashes
from pyaff4 import lexicon
from pyaff4 import aff4_map
from pyaff4 import rdfvalue
from pyaff4 import aff4
from pyaff4 import escaping
from pyaff4.aff4_metadata import RDFObject
from pyaff4 import zip, keybag
from pyaff4.version import Version
from pyaff4 import utils

import yaml
import uuid
import base64
import fastchunking

class Image(object):
    def __init__(self, image, resolver, dataStream):
        self.image = image
        self.urn = image.urn
        self.resolver = resolver
        self.dataStream = dataStream

def parseProperties(propertiesText):
    propertiesText = SmartUnicode(propertiesText)
    res = {}
    for line in propertiesText.split("\n"):
        try:
            (prop, value) = line.split("=")
            res[prop] = value
        except:
            pass
    return res


class Container(object):
    def __init__(self, backing_store, zip_file, version, volumeURN, resolver, lex):
        self.urn = volumeURN
        self.lexicon = lex
        self.resolver = resolver
        self.version = version
        self.closed = False
        # Store references to our dependent zip container and backing store, and manually increment their refcounts
        # Make sure these are released in exit()
        self.backing_store = backing_store
        self.resolver.ObjectCache.Get(self.backing_store.urn)
        self.zip_file = zip_file
        self.resolver.ObjectCache.Get(self.zip_file.urn)


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # Manually release the references we took on construction

        self.resolver.Return(self.zip_file)
        self.resolver.Return(self.backing_store)
        self.resolver.Flush()
        #self.resolver.Return(self.resolver)
        #pass

    def getMetadata(self, klass):
        try:
            m = next(self.resolver.QueryPredicateObject(lexicon.AFF4_TYPE, self.lexicon.of(klass)))
            return RDFObject(m, self.resolver, self.lexicon)
        except:
            return None

    @staticmethod
    def identify(filename):
        """Public method to identify a filename as an AFF4 container."""
        return Container.identifyURN(rdfvalue.URN.FromFileName(filename))


    @staticmethod
    def identifyURN(urn, resolver=None):
        if resolver == None:
            if data_store.HAS_HDT:
                resolver = data_store.HDTAssistedDataStore(lexicon.standard)
            else:
                resolver = data_store.MemoryDataStore(lexicon.standard)

        with resolver as resolver:
            with zip.ZipFile.NewZipFile(resolver, Version(0,1,"pyaff4"), urn) as zip_file:
                if len(list(zip_file.members.keys())) == 0:
                    # it's a new zipfile
                    raise IOError("Not an AFF4 Volume")

                try:
                    with zip_file.OpenZipSegment("version.txt") as version_segment:
                        # AFF4 Std v1.0 introduced the version file
                        versionTxt = version_segment.ReadAll()
                        #resolver.Close(version)
                        version = parseProperties(versionTxt.decode("utf-8"))
                        version = Version.create(version)
                        if version.is11():
                            return (version, lexicon.standard11)
                        else:
                            return (version, lexicon.standard)
                except:
                    if str(resolver.aff4NS) == lexicon.AFF4_NAMESPACE:
                        # Rekall defined the new AFF4 namespace post the Wirespeed paper
                        return (Version(1,0,"pyaff4"), lexicon.scudette)
                    else:
                        # Wirespeed (Evimetry) 1.x and Evimetry 2.x stayed with the original namespace
                        return (Version(0,1,"pyaff4"), lexicon.legacy)

    def isMap(self, stream):
        types = self.resolver.QuerySubjectPredicate(stream, lexicon.AFF4_TYPE)
        if self.lexicon.map in types:
            return True
        return False

    @staticmethod
    def open(filename):
        """Public method to open a filename as an AFF4 container."""
        return Container.openURN(rdfvalue.URN.FromFileName(filename))

    @staticmethod
    def createURN(resolver, container_urn, encryption=False):
        """Public method to create a new writable locical AFF4 container."""

        resolver.Set(lexicon.transient_graph, container_urn, lexicon.AFF4_STREAM_WRITE_MODE, rdfvalue.XSDString("truncate"))

        if encryption == False:
            version = Version(1, 1, "pyaff4")
            with zip.ZipFile.NewZipFile(resolver, version, container_urn) as zip_file:
                volume_urn = zip_file.urn
                with resolver.AFF4FactoryOpen(zip_file.backing_store_urn) as backing_store:
                    return WritableHashBasedImageContainer(backing_store, zip_file, version, volume_urn, resolver, lexicon.standard)
        else:
            version = Version(1, 2, "pyaff4")
            with zip.ZipFile.NewZipFile(resolver, version, container_urn) as zip_file:
                volume_urn = zip_file.urn
                with resolver.AFF4FactoryOpen(zip_file.backing_store_urn) as backing_store:
                    return EncryptedImageContainer(backing_store, zip_file, version, volume_urn, resolver, lexicon.standard)

    @staticmethod
    def openURN(urn):
        return Container.openURNtoContainer(urn).image.dataStream

    @staticmethod
    def new(urn):
        lex = lexicon.standard
        resolver = data_store.MemoryDataStore(lex)
        with zip.ZipFile.NewZipFile(resolver, urn) as zip_file:
            volumeURN = zip_file.urn
            imageURN = next(resolver.QueryPredicateObject(lexicon.AFF4_TYPE, lex.Image))

            datastreams = list(resolver.QuerySubjectPredicate(imageURN, lex.dataStream))
            with resolver.AFF4FactoryOpen(zip_file.backing_store_urn) as backing_store:
                for stream in datastreams:
                    if lex.map in resolver.QuerySubjectPredicate(stream, lexicon.AFF4_TYPE):
                        dataStream = resolver.AFF4FactoryOpen(stream)
                        image = aff4.Image(resolver, urn=imageURN)
                        dataStream.parent = image

                        return PhysicalImageContainer(backing_store, zip_file, volumeURN, zip_file, resolver, lex, image, dataStream)
                

    @staticmethod
    def openURNtoContainer(urn, mode=None):
            if data_store.HAS_HDT:
                resolver = data_store.HDTAssistedDataStore(lexicon.standard)
            else:
                resolver = data_store.MemoryDataStore(lexicon.standard)

            (version, lex) = Container.identifyURN(urn, resolver=resolver)

            resolver.lexicon = lex
            if mode != None and mode == "+":
                resolver.Set(lexicon.transient_graph, urn, lexicon.AFF4_STREAM_WRITE_MODE,
                             rdfvalue.XSDString("random"))

            with zip.ZipFile.NewZipFile(resolver, version, urn) as zip_file:
                with resolver.AFF4FactoryOpen(zip_file.backing_store_urn) as backing_store:
                    volumeURN = zip_file.urn
                    if lex == lexicon.standard or lex == lexicon.standard11:

                        images = list(resolver.QueryPredicateObject(volumeURN, lexicon.AFF4_TYPE, lex.Image))
                        if len(images) > 0:
                            imageURN = images[0]

                            datastreams = list(resolver.QuerySubjectPredicate(volumeURN, imageURN, lex.dataStream))

                            if len(datastreams) > 0:
                                # it is a disk image or a memory image

                                for stream in datastreams:
                                    if lex.map in resolver.QuerySubjectPredicate(volumeURN, stream, lexicon.AFF4_TYPE):
                                        dataStream = resolver.AFF4FactoryOpen(stream)
                                        image = aff4.Image(resolver, urn=imageURN)
                                        dataStream.parent = image

                                        return PhysicalImageContainer(backing_store, zip_file, version, volumeURN, resolver, lex, image, dataStream)

                            else:
                                # it is a logical image
                                if version.is11():
                                    # AFF4 logical images are defined at version 1.1
                                    if mode != None and mode == "+":
                                        return WritableHashBasedImageContainer(backing_store, zip_file, version, volumeURN, resolver, lex)
                                    else:
                                        return LogicalImageContainer(backing_store, zip_file, version, volumeURN, resolver, lex)
                                else:
                                    # scudette's winpmem pre-std implementation is at 1.0
                                    lex = lexicon.pmemlogical
                                    return PreStdLogicalImageContainer(backing_store, zip_file, version, volumeURN, resolver, lex)

                        else:
                            # no images
                            encryptedStreams = list(resolver.QueryPredicateObject(volumeURN, lexicon.AFF4_TYPE, lexicon.standard11.EncryptedStream))
                            if len(encryptedStreams) == 1:
                                encryptedBlockStreamARN = encryptedStreams[0]
                                return EncryptedImageContainer(backing_store, zip_file, version, volumeURN, resolver, lexicon.standard11, encryptedBlockStreamARN, mode)
                            else:
                                return LogicalImageContainer(backing_store, zip_file, version, volumeURN, resolver, lex)


                    elif lex == lexicon.scudette:
                        m = next(resolver.QueryPredicateObject(volumeURN, lexicon.AFF4_TYPE, lex.map))
                        cat = next(resolver.QuerySubjectPredicate(volumeURN, m, lex.category))
                        if cat == lex.memoryPhysical:
                            dataStream = resolver.AFF4FactoryOpen(m)

                            image = aff4.Image(resolver, urn=m)
                            dataStream.parent = image

                            legacyYamlInfoURI = dataStream.urn.Append("information.yaml")
                            try:
                                with resolver.AFF4FactoryOpen(legacyYamlInfoURI) as fd:
                                    txt = fd.read(10000000)
                                    dt = yaml.safe_load(txt)
                                    CR3 = dt["Registers"]["CR3"]
                                    resolver.Add(dataStream.parent.urn, lexicon.standard.memoryPageTableEntryOffset, rdfvalue.XSDInteger(CR3))
                                    kaslr_slide = dt["kaslr_slide"]
                                    resolver.Add(dataStream.parent.urn, lexicon.standard.OSXKALSRSlide, rdfvalue.XSDInteger(kaslr_slide))
                            except:
                                pass

                            return PhysicalImageContainer(backing_store, zip_file, version, volumeURN, resolver, lex, image, dataStream)

    def containsLogicalImage(self, pathfragment):
        arn = self.urn.Append(escaping.arnPathFragment_from_path(pathfragment), quote=False)
        types = self.resolver.Get(lexicon.any, arn, lexicon.AFF4_TYPE)
        if lexicon.standard11.FileImage in types:
            return True
        else:
            return False

class PhysicalImageContainer(Container):
    def __init__(self, backing_store, zip_file, version, volumeURN, resolver, lex, image, dataStream):
        super(PhysicalImageContainer, self).__init__(backing_store, zip_file, version, volumeURN, resolver, lex)
        self.image = Image(image, resolver, dataStream)
        self.dataStream = dataStream

class LogicalImageContainer(Container):
    def __init__(self, backing_store, zip_file, version, volumeURN, resolver, lex):
        super(LogicalImageContainer, self).__init__(backing_store, zip_file, version, volumeURN, resolver, lex)

    def images(self):
        _images = self.resolver.QueryPredicateObject(self.urn, lexicon.AFF4_TYPE, lexicon.standard11.FileImage)
        for image in _images:
            pathName = next(self.resolver.QuerySubjectPredicate(self.urn, image, lexicon.standard11.pathName))
            yield aff4.LogicalImage(self, self.resolver, self.urn, image, pathName)

    def open(self, urn):
        pathName = next(self.resolver.QuerySubjectPredicate(self.urn, urn, lexicon.standard11.pathName))
        return aff4.LogicalImage(self, self.resolver, self.urn, urn, pathName)

    #def __exit__(self, exc_type, exc_value, traceback):
        # Return ourselves to the resolver cache.
        #self.resolver.Flush()
        #return self

class PreStdLogicalImageContainer(LogicalImageContainer):
    def __init__(self, backing_store, zip_file, version, volumeURN, resolver, lex):
        super(PreStdLogicalImageContainer, self).__init__(backing_store, zip_file, version, volumeURN, resolver, lex)

    def images(self):
        _images = self.resolver.QueryPredicateObject(self.urn, lexicon.AFF4_TYPE, lexicon.standard.Image)
        for image in _images:
            pathName = next(self.resolver.QuerySubjectPredicate(self.urn, image, self.lexicon.pathName))
            yield aff4.LogicalImage(self, self.resolver, self.urn, image, pathName)

    def open(self, urn):
        pathName = next(self.resolver.QuerySubjectPredicate(self.urn, urn, self.lexicon.pathName))
        return aff4.LogicalImage(self, self.resolver, self.urn, urn, pathName)

    #def __exit__(self, exc_type, exc_value, traceback):
        # Return ourselves to the resolver cache.
        #self.resolver.Return(self)
        #return self

    def __enter__(self):
        return self

class WritableLogicalImageContainer(Container):

    # logical images geater than this size are stored in ImageStreams
    # smaller ones in Zip Segments
    maxSegmentResidentSize = 1 * 1024 * 1024
    #maxSegmentResidentSize = 1

    def __init__(self, backing_store, zip_file, version, volumeURN, resolver, lex):
        super(WritableLogicalImageContainer, self).__init__(backing_store, zip_file, version, volumeURN, resolver, lex)

        with self.resolver.AFF4FactoryOpen(self.urn) as volume:
            container_description_urn = self.urn.Append("container.description")
            volume.version = self.version

            # create the container description if we aren't appending
            if not volume.ContainsMember(container_description_urn):
                with volume.CreateMember(container_description_urn) as container_description_file:
                    container_description_file.Write(SmartStr(volume.urn.value))
                    container_description_file.Flush()

            # create the version segment if we aren't appending
            version_urn = self.urn.Append("version.txt")
            if not volume.ContainsMember(version_urn):
                with volume.CreateMember(version_urn) as versionFile:
                    # AFF4 logical containers are at v1.1
                    versionFile.Write(SmartStr(str(self.version)))
                    versionFile.Flush()

    # write the logical stream as a compressed block stream using the Stream API
    def writeCompressedBlockStream(self, image_urn, filename, readstream):
        with aff4_image.AFF4Image.NewAFF4Image(self.resolver, image_urn, self.urn) as stream:
            stream.compression = lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY
            stream.WriteStream(readstream)

        # write the logical stream as a zip segment using the Stream API
    def writeZipStream(self, image_urn, filename, readstream):
        with self.resolver.AFF4FactoryOpen(self.urn) as volume:
            with volume.CreateMember(image_urn) as streamed:
                streamed.compression_method = zip.ZIP_DEFLATE
                streamed.WriteStream(readstream)

    # create a file like object for writing a logical image as a new compressed block stream
    def newCompressedBlockStream(self, image_urn, filename):
        stream = aff4_image.AFF4Image.NewAFF4Image(self.resolver, image_urn, self.urn)
        stream.compression = lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY
        return stream

    # create a file like object for writing a logical image as a new zip segment
    def newZipStream(self, image_urn, filename):
        with self.resolver.AFF4FactoryOpen(self.urn) as volume:
            writer = volume.CreateMember(image_urn)
            writer.compression_method = zip.ZIP_DEFLATE
            return writer

    # create a file like object for writing a logical image
    def newLogicalStream(self, filename, length):
        image_urn = None
        if self.isAFF4Collision(filename):
            image_urn = rdfvalue.URN("aff4://%s" % uuid.uuid4())
        else:
            image_urn = self.urn.Append(escaping.arnPathFragment_from_path(filename), quote=False)

        writer = None
        if length > self.maxSegmentResidentSize:
            writer = self.newCompressedBlockStream(image_urn, filename)
        else:
            writer = self.newZipStream(image_urn, filename)
            writer._dirty = True

        self.resolver.Add(self.urn, image_urn, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.standard11.FileImage))
        self.resolver.Add(self.urn, image_urn, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.standard.Image))
        self.resolver.Add(self.urn, image_urn, rdfvalue.URN(lexicon.standard11.pathName), rdfvalue.XSDString(filename))
        return writer

    def writeLogicalStream(self, filename, readstream, length):
        image_urn = None
        if self.isAFF4Collision(filename):
            image_urn = rdfvalue.URN("aff4://%s" % uuid.uuid4())
        else:
            image_urn = self.urn.Append(escaping.arnPathFragment_from_path(filename), quote=False)

        if length > self.maxSegmentResidentSize:
            self.writeCompressedBlockStream(image_urn, filename, readstream)
            self.resolver.Add(self.urn, image_urn, rdfvalue.URN(lexicon.AFF4_TYPE),
                              rdfvalue.URN(lexicon.AFF4_IMAGE_TYPE))
        else:
            self.writeZipStream(image_urn, filename, readstream)
            self.resolver.Add(self.urn, image_urn, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.AFF4_ZIP_SEGMENT_IMAGE_TYPE))

        self.resolver.Add(self.urn, image_urn, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.standard11.FileImage))
        self.resolver.Add(self.urn, image_urn, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.standard.Image))
        self.resolver.Add(self.urn, image_urn, rdfvalue.URN(lexicon.standard11.pathName), rdfvalue.XSDString(filename))
        return image_urn

    def writeLogical(self, filename, readstream, length):
        image_urn = None
        if self.isAFF4Collision(filename):
            image_urn = rdfvalue.URN("aff4://%s" % uuid.uuid4())
        else:
            image_urn = self.urn.Append(escaping.arnPathFragment_from_path(filename), quote=False)

        if length > self.maxSegmentResidentSize:
            self.writeCompressedBlockStream(image_urn, filename, readstream)
        else:
            self.writeZipStream(image_urn, filename, readstream)
            #self.resolver.Set(image_urn, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.AFF4_ZIP_SEGMENT_IMAGE_TYPE))

        self.resolver.Add(self.urn, image_urn, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.standard11.FileImage))
        self.resolver.Add(self.urn, image_urn, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.standard.Image))
        self.resolver.Add(self.urn, image_urn, rdfvalue.URN(lexicon.standard11.pathName), rdfvalue.XSDString(filename))
        return image_urn

    def isAFF4Collision(self, filename):
        if filename in ["information.turtle", "version.txt", "container.description"]:
            return True
        return False

    def images(self):
        _images = self.resolver.QueryPredicateObject(self.urn, lexicon.AFF4_TYPE, lexicon.standard11.FileImage)
        for image in _images:
            pathName = next(self.resolver.QuerySubjectPredicate(self.urn, image, lexicon.standard11.pathName))
            yield aff4.LogicalImage(self, self.resolver, self.urn, image, pathName)

class WritableHashBasedImageContainer(WritableLogicalImageContainer):
    def __init__(self, backing_store, zip_file, version, volumeURN, resolver, lex):
        super(WritableHashBasedImageContainer, self).__init__(backing_store, zip_file, version, volumeURN, resolver, lex)
        block_store_stream_id = "aff4://%s" % uuid.uuid4()
        self.block_store_stream = aff4_image.AFF4Image.NewAFF4Image(resolver, block_store_stream_id, self.urn)
        self.block_store_stream.compression = lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY

    def preserveChunk(self, logical_file_map, chunk, chunk_offset, chunk_hash, check_bytes):
        # we use RFC rfc4648
        hashid = rdfvalue.URN("aff4:sha512:" + base64.urlsafe_b64encode(chunk_hash.digest()).decode())

        # check if this hash is in the container already
        existing_bytestream_reference_id = self.resolver.GetUnique(lexicon.any, hashid,
                                                                   rdfvalue.URN(lexicon.standard.dataStream))

        if existing_bytestream_reference_id == None:
            block_stream_address = self.block_store_stream.TellWrite()
            self.block_store_stream.Write(chunk)

            chunk_reference_id = self.block_store_stream.urn.SerializeToString() + "[0x%x:0x%x]" % (
            block_stream_address, len(chunk))
            chunk_reference_id = rdfvalue.URN(chunk_reference_id)
            self.resolver.Add(self.urn, hashid, rdfvalue.URN(lexicon.standard.dataStream), chunk_reference_id)

            logical_file_map.AddRange(chunk_offset, 0, len(chunk), hashid)
            # print("[%x, %x] -> %s -> %s" % (file_offset, toread, hashid, chunk_reference_id))
        else:
            if check_bytes:
                with self.resolver.AFF4FactoryOpen(existing_bytestream_reference_id) as existing_chunk_stream:
                    existing_chunk_length = existing_chunk_stream.length
                    existing_chunk = existing_chunk_stream.Read(existing_chunk_length)

                    if chunk != existing_chunk:
                        # we hit the jackpot and found a hash collision
                        # in this highly unlikely event, we store the new bytes using regular logical
                        # imaging. To record the collision, we add the colliding stream as a property
                        print("!!!Collision found for hash %s" % hashid)
                        block_stream_address = self.block_store_stream.TellWrite()
                        self.block_store_stream.Write(chunk)

                        chunk_reference_id = self.block_store_stream.urn.SerializeToString() + "[0x%x:0x%x]" % (
                            block_stream_address, len(chunk))
                        chunk_reference_id = rdfvalue.URN(chunk_reference_id)
                        logical_file_map.AddRange(chunk_offset, block_stream_address, len(chunk),
                                                  self.block_store_stream.urn)

                        self.resolver.Add(self.urn, hashid, rdfvalue.URN(lexicon.standard11.collidingDataStream),
                                          chunk_reference_id)
                    else:
                        logical_file_map.AddRange(chunk_offset, 0, len(chunk), hashid)
            else:
                logical_file_map.AddRange(chunk_offset, 0, len(chunk), hashid)

    def writeLogicalStreamRabinHashBased(self, filename, readstream, length, check_bytes=False):
        logical_file_id = None
        if self.isAFF4Collision(filename):
            logical_file_id = rdfvalue.URN("aff4://%s" % uuid.uuid4())
        else:
            logical_file_id = self.urn.Append(escaping.arnPathFragment_from_path(filename), quote=False)

        chunk_size = 32*1024
        cdc = fastchunking.RabinKarpCDC(window_size=48, seed=0)
        chunker = cdc.create_chunker(chunk_size=4096)


        with aff4_map.AFF4Map.NewAFF4Map(
                self.resolver, logical_file_id, self.urn) as logical_file_map:
            file_offset = 0
            lastbuffer = None
            lastoffset = 0
            chunk_offset = 0
            while file_offset < length:
                toread = min(length-file_offset, chunk_size)
                buffer = readstream.read(toread)

                foundBoundaries = False
                for boundary in chunker.next_chunk_boundaries(buffer):
                    foundBoundaries = True

                    if lastbuffer != None:
                        l = len(lastbuffer)
                        chunk = lastbuffer[lastoffset:]
                        chunk_offset = file_offset - len(chunk)
                        chunk = chunk + buffer[:boundary]
                        lastbuffer = None
                    else:
                        chunk = buffer[lastoffset:boundary]
                        chunk_offset = file_offset + lastoffset

                    h = hashes.new(lexicon.HASH_SHA512)
                    h.update(chunk)

                    self.preserveChunk(logical_file_map, chunk, chunk_offset, h, check_bytes)

                    lastoffset = boundary

                if not foundBoundaries:
                    if lastbuffer != None:
                        lastbuffer = lastbuffer + buffer
                    else:
                        lastbuffer = buffer
                else:
                    lastbuffer = buffer
                file_offset += toread


            if lastbuffer != None and lastoffset < len(lastbuffer):
                chunk = lastbuffer[lastoffset:]
                chunk_offset = file_offset - len(chunk)
                h = hashes.new(lexicon.HASH_SHA512)
                h.update(chunk)
                self.preserveChunk(logical_file_map, chunk, chunk_offset, h, check_bytes)

        logical_file_map.Close()

        self.resolver.Add(self.urn, logical_file_id, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.standard11.FileImage))
        self.resolver.Add(self.urn, logical_file_id, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.standard.Image))
        self.resolver.Add(self.urn, logical_file_id, rdfvalue.URN(lexicon.standard11.pathName), rdfvalue.XSDString(filename))
        return logical_file_id

    def writeLogicalStreamHashBased(self, filename, readstream, length, check_bytes=False):
        logical_file_id = None
        if self.isAFF4Collision(filename):
            logical_file_id = rdfvalue.URN("aff4://%s" % uuid.uuid4())
        else:
            logical_file_id = self.urn.Append(escaping.arnPathFragment_from_path(filename), quote=False)

        chunk_size = self.block_store_stream.chunk_size

        with aff4_map.AFF4Map.NewAFF4Map(
                self.resolver, logical_file_id, self.urn) as logical_file_map:
            file_offset = 0
            while file_offset < length:
                toread = min(length-file_offset, chunk_size)
                chunk = readstream.read(toread)

                # pad the chunk to chunksize if it is small
                read_chunk_size = len(chunk)
                if read_chunk_size < chunk_size:
                    chunk = chunk + b"\x00" * (chunk_size - read_chunk_size)

                h = hashes.new(lexicon.HASH_SHA512)
                h.update(chunk)
                # we use RFC rfc4648
                hashid = rdfvalue.URN("aff4:sha512:" + base64.urlsafe_b64encode(h.digest()).decode())

                # check if this hash is in the container already
                existing_bytestream_reference_id =  self.resolver.GetUnique(lexicon.any, hashid, rdfvalue.URN(lexicon.standard.dataStream))

                if existing_bytestream_reference_id == None:
                    block_stream_address = self.block_store_stream.TellWrite()
                    self.block_store_stream.Write(chunk)

                    chunk_reference_id = self.block_store_stream.urn.SerializeToString() + "[0x%x:0x%x]" % (block_stream_address, chunk_size)
                    chunk_reference_id = rdfvalue.URN(chunk_reference_id)
                    self.resolver.Add(self.urn, hashid, rdfvalue.URN(lexicon.standard.dataStream), chunk_reference_id)

                    logical_file_map.AddRange(file_offset, 0, toread, hashid)
                    #print("[%x, %x] -> %s -> %s" % (file_offset, toread, hashid, chunk_reference_id))
                else:
                    if check_bytes:
                        with self.resolver.AFF4FactoryOpen(existing_bytestream_reference_id) as existing_chunk_stream:
                            existing_chunk_length = existing_chunk_stream.length
                            existing_chunk = existing_chunk_stream.Read(existing_chunk_length)

                            if chunk != existing_chunk:
                                # we hit the jackpot and found a hash collision
                                # in this highly unlikely event, we store the new bytes using regular logical
                                # imaging. To record the collision, we add the colliding stream as a property
                                print("!!!Collision found for hash %s" % hashid)
                                block_stream_address = self.block_store_stream.TellWrite()
                                self.block_store_stream.Write(chunk)

                                chunk_reference_id = self.block_store_stream.urn.SerializeToString() + "[0x%x:0x%x]" % (
                                block_stream_address, chunk_size)
                                chunk_reference_id = rdfvalue.URN(chunk_reference_id)
                                logical_file_map.AddRange(file_offset, block_stream_address, chunk_size, self.block_store_stream.urn)

                                self.resolver.Add(self.urn, hashid, rdfvalue.URN(lexicon.standard11.collidingDataStream),
                                                  chunk_reference_id)
                            else:
                                logical_file_map.AddRange(file_offset, 0, toread, hashid)
                    else:
                        logical_file_map.AddRange(file_offset, 0, toread, hashid)
                    #print("[%x, %x] -> %s -> %s" % (file_offset, toread, hashid, existing_bytestream_reference_id))

                file_offset += toread

        logical_file_map.Close()

        self.resolver.Add(self.urn, logical_file_id, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.standard11.FileImage))
        self.resolver.Add(self.urn, logical_file_id, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.standard.Image))
        self.resolver.Add(self.urn, logical_file_id, rdfvalue.URN(lexicon.standard11.pathName), rdfvalue.XSDString(filename))
        return logical_file_id

    def __exit__(self, exc_type, exc_value, traceback):
        # Return ourselves to the resolver cache.
        self.resolver.Return(self.block_store_stream)
        return super(WritableHashBasedImageContainer, self).__exit__(exc_type, exc_value, traceback)

class EncryptedImageContainer(Container):
    def __init__(self, backing_store, zip_file, version, volumeURN, resolver, lex, encryptedBlockStreamARN=None, mode=None):
        super(EncryptedImageContainer, self).__init__(backing_store, zip_file, version, volumeURN, resolver, lex)
        self.childContainer = None
        self.mode = mode
        self.initial_debug_state = None

        with self.resolver.AFF4FactoryOpen(self.urn) as volume:
            container_description_urn = self.urn.Append("container.description")
            volume.version = self.version

            # create the container description if we aren't appending
            if not volume.ContainsMember(container_description_urn):
                with volume.CreateMember(container_description_urn) as container_description_file:
                    container_description_file.Write(SmartStr(volume.urn.value))
                    container_description_file.Flush()

            # create the version segment if we aren't appending
            version_urn = self.urn.Append("version.txt")
            if not volume.ContainsMember(version_urn):
                with volume.CreateMember(version_urn) as versionFile:
                    # AFF4 logical containers are at v1.1
                    versionFile.Write(SmartStr(str(self.version)))
                    versionFile.Flush()


        if encryptedBlockStreamARN == None:
            encrypted_block_store_ARN = "aff4://%s" % uuid.uuid4()

            if self.mode != None and self.mode == "+":
                resolver.Set(lexicon.transient_graph, encrypted_block_store_ARN, lexicon.AFF4_STREAM_WRITE_MODE,
                             rdfvalue.XSDString("random"))
            else:
                self.mode = "w"
                resolver.Set(lexicon.transient_graph, encrypted_block_store_ARN, lexicon.AFF4_STREAM_WRITE_MODE,
                             rdfvalue.XSDString("truncate"))

            self.block_store_stream = aff4_image.AFF4Image.NewAFF4Image(resolver, encrypted_block_store_ARN, self.urn,
                                                                        type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE)
            self.block_store_stream.chunk_size = 512
            self.block_store_stream.chunks_per_segment = 2048

        else:
            # loading
            encrypted_block_store_ARN = encryptedBlockStreamARN

            isWritable = True
            if self.mode != None and self.mode == "+":
                resolver.Set(lexicon.transient_graph, encrypted_block_store_ARN, lexicon.AFF4_STREAM_WRITE_MODE,
                             rdfvalue.XSDString("random"))
            else:
                # regular read only open path
                isWritable = False

            self.block_store_stream = aff4_image.AFF4Image.NewAFF4Image(resolver, encrypted_block_store_ARN, self.urn,
                                                                        type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE)
            self.block_store_stream.properties.writable = isWritable
            for kbARN in self.resolver.Get(volumeURN, encrypted_block_store_ARN, lex.keyBag):
                typ = self.resolver.GetUnique(volumeURN, kbARN, lexicon.AFF4_TYPE)
                if typ == lexicon.standard11.PasswordWrappedKeyBag:
                    kb = keybag.PasswordWrappedKeyBag.loadFromResolver(resolver, volumeURN, kbARN)
                    self.block_store_stream.addKeyBag(kb)
                elif typ == lexicon.standard11.CertEncryptedKeyBag:
                    kb = keybag.CertEncryptedKeyBag.loadFromResolver(resolver, volumeURN, kbARN)
                    self.block_store_stream.addKeyBag(kb)

    def init_child(self):
        self.initial_debug_state = self.block_store_stream.DEBUG
        self.childResolver = data_store.MemoryDataStore(parent = self.resolver)

        with zip.ZipFile.NewZipFile(self.childResolver, self.version, self.block_store_stream.urn, appendmode=self.mode) as self.childZip:
            #resolver.Set(lexicon.transient_graph, self.childZip.urn, lexicon.AFF4_TYPE,
            #            rdfvalue.URN(lexicon.AFF4_ZIP_TYPE))

            #self.resolver.Set(lexicon.transient_graph, self.block_store_stream.urn, lexicon.AFF4_STORED,
            #             self.childZip.urn)

            if self.mode != None:
                if self.mode == "+" or self.mode == "w":
                    # explicitly set writable as the above factory allocates its ARN dynamically, so
                    # we cant setup the right relationship
                    self.childZip.properties.writable = True
                    self.childContainer = WritableLogicalImageContainer(self.block_store_stream, self.childZip, self.version, self.childZip.urn, self.childResolver,
                                                                    lexicon.standard11)

            else:
                self.childContainer =  LogicalImageContainer(self.block_store_stream, self.childZip, self.version, self.childZip.urn, self.childResolver,
                                                                lexicon.standard11)

    def __exit__(self, exc_type, exc_value, traceback):
        # Return ourselves to the resolver cache.
        if self.childContainer != None:
            self.childContainer.__exit__(exc_type, exc_value, traceback)

        # return the block_store_stream once to match reference counting
        self.resolver.Return(self.block_store_stream)

        return super(EncryptedImageContainer, self).__exit__(exc_type, exc_value, traceback)

    def setPassword(self, password):
        if len(self.block_store_stream.keybags) > 0:
            for passKeyBag in filter(lambda x: type(x) == keybag.PasswordWrappedKeyBag, self.block_store_stream.keybags):
                vek = passKeyBag.unwrap_key(password)
                self.block_store_stream.setKey(vek)
        else:
            kb = keybag.PasswordWrappedKeyBag.create(password)
            self.block_store_stream.setKeyBag(kb)
            self.block_store_stream.setKey(kb.unwrap_key(password))
        self.init_child()

    def setPublicKeyCert(self, publicKeyCert):
        passKeyBag = next(filter(lambda x: type(x) == keybag.PasswordWrappedKeyBag, self.block_store_stream.keybags))
        kb = keybag.CertEncryptedKeyBag.create(self.block_store_stream.vek, passKeyBag.keySizeBytes, publicKeyCert)
        kb.write(self.resolver, self.block_store_stream.urn)
        self.resolver.Add(self.urn, self.block_store_stream.urn, lexicon.standard11.keyBag, kb.ID)

    def setPrivateKey(self, privateKey):
        for certKeyBag in filter(lambda x: type(x) == keybag.CertEncryptedKeyBag, self.block_store_stream.keybags):
            vek = certKeyBag.unwrap_key(privateKey)
            self.block_store_stream.setKey(vek)
        self.init_child()

    def getChildContainer(self):
        if self.initial_debug_state != None and (self.initial_debug_state != self.block_store_stream.DEBUG):
            raise RuntimeError("The debug status of the encrypted stream has been changed after initialization.")
        return self.childContainer