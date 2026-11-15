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

from rdflib import Literal, XSD

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
from pyaff4.rdfvalue import ARN
from pyaff4.aff4 import MemberContainer

import yaml
import uuid
import base64

class Image:
    def __init__(self, image, resolver, dataStream):
        self.image = image
        self.urn = image.urn
        self.resolver = resolver
        self.dataStream = dataStream

def parseProperties(propertiesText):
    res = {}
    for line in propertiesText.split("\n"):
        try:
            (prop, value) = line.split("=")
            res[prop] = value
        except ValueError:
            pass
    return res


class Container:
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
        #pass

    def getMetadata(self, klass):
        try:
            m = next(self.resolver.QueryPredicateObject(self.urn, lexicon.AFF4_TYPE, self.lexicon.of(klass)))
            return RDFObject(m, self.resolver, self.lexicon)
        except StopIteration:
            return None

    @staticmethod
    def identify(filename):
        """Public method to identify a filename as an AFF4 container."""
        return Container.identifyURN(rdfvalue.URN.FromFileName(filename))

    @staticmethod
    def identifyURNFromZip(zip_file, resolver=None):
        if len(list(zip_file.members.keys())) == 0:
            # it's a new zipfile
            raise IOError("Not an AFF4 Volume")

        try:
            with zip_file.OpenZipSegment("version.txt") as version_segment:
                # AFF4 Std v1.0 introduced the version file
                versionTxt = version_segment.ReadAll()
                version = parseProperties(versionTxt.decode("utf-8"))
                version = Version.create(version)
                if version.is11():
                    if version.tool == "pyaff4":
                        return (zip_file.urn, version, lexicon.standard11)
                    return (zip_file.urn, version, lexicon.interimAff4l)
                else:
                    return (zip_file.urn, version, lexicon.standard)
        except Exception:
            if str(resolver.aff4NS) == lexicon.AFF4_NAMESPACE:
                # Rekall defined the new AFF4 namespace post the Wirespeed paper
                return (zip_file.urn, Version(1,0,"pyaff4"), lexicon.scudette)
            else:
                # Wirespeed (Evimetry) 1.x and Evimetry 2.x stayed with the original namespace
                return (zip_file.urn, Version(0,1,"pyaff4"), lexicon.legacy)

    @staticmethod
    def identifyURN(urn, resolver=None):
        if resolver is None:
            if data_store.HAS_HDT:
                resolver = data_store.HDTAssistedDataStore(lexicon.standard)
            else:
                resolver = data_store.MemoryDataStore(lexicon.standard)

        with resolver as resolver:
            with zip.ZipFile.NewZipFile(resolver, Version(0,1,"pyaff4"), urn) as zip_file:
                return Container.identifyURNFromZip(zip_file, resolver=resolver)

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
    def createURN(resolver, container_urn, encryption=False, hashbased=False,
                  zipstream_compression_method=zip.ZIP_DEFLATE, always_write_zipstreams=False):
        """Public method to create a new writable locical AFF4 container.

        zipstream_compression_method and always_write_zipstreams configure the
        WritableLogicalImageContainer returned when neither encryption nor hashbased is set.
        """
        zipstream_compression_method = zip_compression_method(zipstream_compression_method)
        if (encryption or hashbased) and (
                zipstream_compression_method != zip.ZIP_DEFLATE or always_write_zipstreams):
            raise ValueError(
                "zipstream_compression_method and always_write_zipstreams only apply to logical "
                "containers, not with encryption or hashbased")

        if encryption == False:
            version = Version(1, 1, "pyaff4")
            with zip.ZipFile.NewZipFile(resolver, version, container_urn, appendmode="truncate") as zip_file:
                with ZipMemberContainer(resolver, None, zip_file, version=version) as member_container:
                    volume_urn = member_container.urn
                    backing_store = zip_file.parent
                    if hashbased:
                        from pyaff4 import dedup_container
                        return dedup_container.WritableHashBasedImageContainer(backing_store, zip_file, version, volume_urn, resolver, lexicon.standard)
                    else:
                        return WritableLogicalImageContainer(
                            backing_store, zip_file, version, volume_urn, resolver,
                            lexicon.standard,
                            zipstream_compression_method=zipstream_compression_method,
                            always_write_zipstreams=always_write_zipstreams)
        else:
            version = Version(1, 2, "pyaff4")
            with zip.ZipFile.NewZipFile(resolver, version, container_urn, appendmode="truncate") as zip_file:
                with ZipMemberContainer(resolver, None, zip_file, version=version) as member_container:
                    volume_urn = member_container.urn
                    backing_store = zip_file.parent
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
            imageURN = next(resolver.QueryPredicateObject(volumeURN, lexicon.AFF4_TYPE, lex.Image))

            datastreams = list(resolver.QuerySubjectPredicate(imageURN, lex.dataStream))
            with resolver.AFF4FactoryOpen(zip_file.backing_store_urn) as backing_store:
                for stream in datastreams:
                    if lex.map in resolver.QuerySubjectPredicate(stream, lexicon.AFF4_TYPE):
                        dataStream = resolver.AFF4FactoryOpen(stream)
                        image = aff4.Image(resolver, urn=imageURN)
                        dataStream.parent = image

                        return PhysicalImageContainer(backing_store, zip_file, volumeURN, zip_file, resolver, lex, image, dataStream)
                

    @staticmethod
    def openURNtoContainer(backing_store_arn, mode=None, hashbased=False):
            if data_store.HAS_HDT:
                resolver = data_store.HDTAssistedDataStore(lexicon.standard)
            else:
                resolver = data_store.MemoryDataStore(lexicon.standard)

            appendmode = None
            if mode is not None and mode == "+":
                appendmode = "random"

            # Open the zip once and identify against the open instance,
            # rather than calling identifyURN (which opens, parses, then
            # closes) followed by a second NewZipFile.
            with zip.ZipFile.NewZipFile(resolver, None, backing_store_arn, appendmode=appendmode) as zip_file:
                (arn, version, lex) = Container.identifyURNFromZip(zip_file, resolver=resolver)
                resolver.lexicon = lex
                zip_file.version = version
                backing_store = zip_file.parent
                with ZipMemberContainer(resolver, arn, zip_file, version=version) as member_container:
                    volumeURN = member_container.urn

                    if lex in (lexicon.standard, lexicon.standard11, lexicon.interimAff4l):

                        imageURN = next(iter(resolver.QueryPredicateObject(
                            volumeURN, lexicon.AFF4_TYPE, lex.Image)), None)
                        if imageURN is not None:

                            datastreams = list(resolver.QuerySubjectPredicate(volumeURN, imageURN, lex.dataStream))

                            if len(datastreams) > 0:
                                # it is a disk image or a memory image

                                for stream in datastreams:
                                    if lex.map in resolver.QuerySubjectPredicate(volumeURN, stream, lexicon.AFF4_TYPE):
                                        dataStream = resolver.AFF4FactoryOpen(stream)
                                        image = aff4.Image(resolver, imageURN, member_container)
                                        dataStream.parent = image

                                        return PhysicalImageContainer(member_container, backing_store, zip_file, version, volumeURN, resolver, lex, image, dataStream)

                            else:
                                # it is a logical image
                                if version.is11():
                                    # AFF4 logical images are defined at version 1.1
                                    if mode is not None and mode == "+":
                                        if hashbased:
                                            from pyaff4 import dedup_container
                                            return dedup_container.WritableHashBasedImageContainer(backing_store, zip_file, version, volumeURN, resolver, lex)
                                        else:
                                            return WritableLogicalImageContainer(backing_store, zip_file, version, volumeURN, resolver, lex)
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
                                    resolver.Add(dataStream.parent.urn, lexicon.standard.memoryPageTableEntryOffset, Literal(CR3, datatype=XSD.integer))
                                    kaslr_slide = dt["kaslr_slide"]
                                    resolver.Add(dataStream.parent.urn, lexicon.standard.OSXKALSRSlide, Literal(kaslr_slide, datatype=XSD.integer))
                            except (IOError, KeyError, yaml.YAMLError):
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
    def __init__(self, member_container, backing_store, zip_file, version, volumeURN, resolver, lex, image, dataStream):
        super().__init__(backing_store, zip_file, version, volumeURN, resolver, lex)
        self.image = Image(image, resolver, dataStream)
        self.dataStream = dataStream
        self.member_container = member_container

    def __exit__(self, exc_type, exc_value, traceback):
        self.resolver.Return(self.dataStream)
        self.member_container.Close()
        return False

class LogicalImageContainer(Container):
    def __init__(self, backing_store, zip_file, version, volumeURN, resolver, lex):
        super().__init__(backing_store, zip_file, version, volumeURN, resolver, lex)

    def images(self):
        _images = self.resolver.QueryPredicateObject(self.urn, lexicon.AFF4_TYPE, lexicon.standard11.FileImage)
        for image in _images:
            pathName = next(self.resolver.QuerySubjectPredicate(self.urn, image, self.lexicon.pathName))
            yield aff4.LogicalImage(self, self.resolver, self.urn, image, pathName.toPython())

    def open(self, urn):
        pathName = next(self.resolver.QuerySubjectPredicate(self.urn, urn, self.lexicon.pathName))
        return aff4.LogicalImage(self, self.resolver, self.urn, urn, pathName.toPython())

    #def __exit__(self, exc_type, exc_value, traceback):
        # Return ourselves to the resolver cache.
        #return self

class PreStdLogicalImageContainer(LogicalImageContainer):
    def __init__(self, backing_store, zip_file, version, volumeURN, resolver, lex):
        super().__init__(backing_store, zip_file, version, volumeURN, resolver, lex)

    def images(self):
        _images = self.resolver.QueryPredicateObject(self.urn, lexicon.AFF4_TYPE, lexicon.standard.Image)
        for image in _images:
            pathName = next(self.resolver.QuerySubjectPredicate(self.urn, image, self.lexicon.pathName))
            yield aff4.LogicalImage(self, self.resolver, self.urn, image, pathName.toPython())

    def open(self, urn):
        pathName = next(self.resolver.QuerySubjectPredicate(self.urn, urn, self.lexicon.pathName))
        return aff4.LogicalImage(self, self.resolver, self.urn, urn, pathName.toPython())

    #def __exit__(self, exc_type, exc_value, traceback):
        # Return ourselves to the resolver cache.
        #return self

    def __enter__(self):
        return self

def zip_compression_method(method):
    """The zip compression method for a zipstream_compression_method setting.

    Accepts the AFF4 lexicon's stored compression as a synonym for zip.ZIP_STORED, as
    ZipFileSegment.setCompressionMethod does.
    """
    if method in (zip.ZIP_STORED, lexicon.AFF4_IMAGE_COMPRESSION_STORED):
        return zip.ZIP_STORED
    if method == zip.ZIP_DEFLATE:
        return zip.ZIP_DEFLATE
    raise ValueError(
        "zipstream_compression_method must be zip.ZIP_DEFLATE, zip.ZIP_STORED or "
        f"lexicon.AFF4_IMAGE_COMPRESSION_STORED, not {method!r}")


class WritableLogicalImageContainer(Container):

    # logical images geater than this size are stored in ImageStreams
    # smaller ones in Zip Segments
    maxSegmentResidentSize = 1 * 1024 * 1024

    # How logical images written as zip streams are compressed: zip.ZIP_DEFLATE or zip.ZIP_STORED.
    # The constructor also accepts lexicon.AFF4_IMAGE_COMPRESSION_STORED for zip.ZIP_STORED.
    zipstream_compression_method = zip.ZIP_DEFLATE
    # Write every logical image as a zip stream, whatever its size, so that zip tools can extract
    # the files directly.
    always_write_zipstreams = False

    def __init__(self, backing_store, zip_file, version, volumeURN, resolver, lex,
                 zipstream_compression_method=zip.ZIP_DEFLATE, always_write_zipstreams=False):
        zipstream_compression_method = zip_compression_method(zipstream_compression_method)
        super().__init__(backing_store, zip_file, version, volumeURN, resolver, lex)
        self.zipstream_compression_method = zipstream_compression_method
        self.always_write_zipstreams = always_write_zipstreams

        with self.resolver.AFF4FactoryOpen(self.urn) as volume:
            container_description_urn = self.urn.Append("container.description")
            volume.version = self.version

            # create the container description if we aren't appending
            if not volume.ContainsMember(container_description_urn):
                with volume.CreateMember(container_description_urn) as container_description_file:
                    container_description_file.Write(volume.urn.toPython().encode("utf-8"))
                    container_description_file.Flush()

            # create the version segment if we aren't appending
            version_urn = self.urn.Append("version.txt")
            if not volume.ContainsMember(version_urn):
                with volume.CreateMember(version_urn) as versionFile:
                    # AFF4 logical containers are at v1.1
                    versionFile.Write(str(self.version).encode("utf-8"))
                    versionFile.Flush()

    # write the logical stream as a compressed block stream using the Stream API
    def writeCompressedBlockStream(self, image_urn, filename, readstream, progress=None):
        with self.resolver.AFF4FactoryOpen(self.urn) as volume:
            with aff4_image.AFF4Image.NewAFF4Image(self.resolver, volume, image_urn, self.urn) as stream:
                stream.compression = lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY
                stream.WriteStream(readstream, progress=progress)

        # write the logical stream as a zip segment using the Stream API
    def writeZipStream(self, image_urn, filename, readstream, progress=None):
        with self.resolver.AFF4FactoryOpen(self.urn) as volume:
            with volume.CreateMember(image_urn) as streamed:
                streamed.compression_method = self.zipstream_compression_method
                streamed.WriteStream(readstream, progress=progress)

    # create a file like object for writing a logical image as a new compressed block stream
    def newCompressedBlockStream(self, image_urn, filename):
        with self.resolver.AFF4FactoryOpen(self.urn) as volume:
            stream = aff4_image.AFF4Image.NewAFF4Image(self.resolver, volume, image_urn, self.urn)
            stream.compression = lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY
            return stream

    # create a file like object for writing a logical image as a new zip segment
    def newZipStream(self, image_urn, filename):
        with self.resolver.AFF4FactoryOpen(self.urn) as volume:
            writer = volume.CreateMember(image_urn)
            writer.compression_method = self.zipstream_compression_method
            return writer

    # create a file like object for writing a logical image
    def newLogicalStream(self, filename, length):
        image_urn = None
        if self.isAFF4Collision(filename):
            image_urn = ARN("aff4://%s" % uuid.uuid4())
        else:
            image_urn = self.urn.Append(escaping.arnPathFragment_from_path(filename), quote=False)

        writer = None
        if length > self.maxSegmentResidentSize and not self.always_write_zipstreams:
            writer = self.newCompressedBlockStream(image_urn, filename)
        else:
            writer = self.newZipStream(image_urn, filename)
            writer._dirty = True

        self.resolver.Add(self.urn, image_urn, lexicon.AFF4_TYPE, lexicon.standard11.FileImage)
        self.resolver.Add(self.urn, image_urn, lexicon.AFF4_TYPE, lexicon.standard.Image)
        self.resolver.Add(self.urn, image_urn, lexicon.standard11.pathName, Literal(filename))
        return writer

    def writeLogicalStream(self, filename, readstream, length, progress=None):
        image_urn = None
        if self.isAFF4Collision(filename):
            image_urn = rdfvalue.URN("aff4://%s" % uuid.uuid4())
        else:
            image_urn = self.urn.Append(escaping.arnPathFragment_from_path(filename), quote=False)

        if length > self.maxSegmentResidentSize and not self.always_write_zipstreams:
            self.writeCompressedBlockStream(image_urn, filename, readstream, progress=progress)
            self.resolver.Add(self.urn, image_urn, lexicon.AFF4_TYPE,
                              lexicon.AFF4_IMAGE_TYPE)
        else:
            self.writeZipStream(image_urn, filename, readstream, progress=progress)
            self.resolver.Add(self.urn, image_urn, lexicon.AFF4_TYPE, lexicon.AFF4_ZIP_SEGMENT_IMAGE_TYPE)

        self.resolver.Add(self.urn, image_urn, lexicon.AFF4_TYPE, lexicon.standard11.FileImage)
        self.resolver.Add(self.urn, image_urn, lexicon.AFF4_TYPE, lexicon.standard.Image)
        self.resolver.Add(self.urn, image_urn, lexicon.standard11.pathName, Literal(filename))
        return image_urn

    def writeLogical(self, filename, readstream, length):
        image_urn = None
        if self.isAFF4Collision(filename):
            image_urn = ARN("aff4://%s" % uuid.uuid4())
        else:
            image_urn = self.urn.Append(escaping.arnPathFragment_from_path(filename), quote=False)

        if length > self.maxSegmentResidentSize:
            self.writeCompressedBlockStream(image_urn, filename, readstream)
        else:
            self.writeZipStream(image_urn, filename, readstream)

        self.resolver.Add(self.urn, image_urn, lexicon.AFF4_TYPE, lexicon.standard11.FileImage)
        self.resolver.Add(self.urn, image_urn, lexicon.AFF4_TYPE, lexicon.standard.Image)
        self.resolver.Add(self.urn, image_urn, lexicon.standard11.pathName, Literal(filename))
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

class EncryptedImageContainer(Container):
    def __init__(self, backing_store, zip_file, version, volumeURN, resolver, lex, encryptedBlockStreamARN=None, mode=None):
        super().__init__(backing_store, zip_file, version, volumeURN, resolver, lex)
        self.childContainer = None
        self.mode = mode
        self.initial_debug_state = None

        with self.resolver.AFF4FactoryOpen(self.urn) as volume:
            container_description_urn = self.urn.Append("container.description")
            volume.version = self.version

            # create the container description if we aren't appending
            if not volume.ContainsMember(container_description_urn):
                with volume.CreateMember(container_description_urn) as container_description_file:
                    container_description_file.Write(volume.urn.toPython().encode("utf-8"))
                    container_description_file.Flush()

            # create the version segment if we aren't appending
            version_urn = self.urn.Append("version.txt")
            if not volume.ContainsMember(version_urn):
                with volume.CreateMember(version_urn) as versionFile:
                    # AFF4 logical containers are at v1.1
                    versionFile.Write(str(self.version).encode("utf-8"))
                    versionFile.Flush()


        if encryptedBlockStreamARN is None:
            encrypted_block_store_ARN = ARN("aff4://%s" % uuid.uuid4())

            if self.mode is not None and self.mode == "+":
                resolver.Set(lexicon.transient_graph, encrypted_block_store_ARN, lexicon.AFF4_STREAM_WRITE_MODE,
                             Literal("random"))
            else:
                self.mode = "w"
                resolver.Set(lexicon.transient_graph, encrypted_block_store_ARN, lexicon.AFF4_STREAM_WRITE_MODE,
                             Literal("truncate"))

            with self.resolver.AFF4FactoryOpen(self.urn) as volume:
                self.block_store_stream = aff4_image.AFF4Image.NewAFF4Image(resolver, volume, encrypted_block_store_ARN, self.urn,
                                                                            type=lexicon.AFF4_ENCRYPTEDSTREAM_TYPE)
            self.block_store_stream.chunk_size = 512
            self.block_store_stream.chunks_per_segment = 2048

        else:
            # loading
            encrypted_block_store_ARN = encryptedBlockStreamARN

            isWritable = True
            if self.mode is not None and self.mode == "+":
                resolver.Set(lexicon.transient_graph, encrypted_block_store_ARN, lexicon.AFF4_STREAM_WRITE_MODE,
                             Literal("random"))
            else:
                # regular read only open path
                isWritable = False

            with self.resolver.AFF4FactoryOpen(self.urn) as volume:
                self.block_store_stream = aff4_image.AFF4Image.NewAFF4Image(resolver, volume, encrypted_block_store_ARN, self.urn,
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
            self.childMemberContainer = ZipMemberContainer(
                self.childResolver, None, self.childZip, version=self.version)

            if self.mode is not None:
                if self.mode == "+" or self.mode == "w":
                    # explicitly set writable as the above factory allocates its ARN dynamically, so
                    # we cant setup the right relationship
                    self.childZip.properties.writable = True
                    self.childContainer = WritableLogicalImageContainer(
                        self.block_store_stream, self.childZip, self.version,
                        self.childMemberContainer.urn, self.childResolver,
                        lexicon.standard11)

            else:
                self.childContainer = LogicalImageContainer(
                    self.block_store_stream, self.childZip, self.version,
                    self.childMemberContainer.urn, self.childResolver,
                    lexicon.standard11)

    def __exit__(self, exc_type, exc_value, traceback):
        # Return ourselves to the resolver cache.
        if self.childContainer is not None:
            self.childContainer.__exit__(exc_type, exc_value, traceback)

        # The childMemberContainer was held in_use by ZipMemberContainer's
        # constructor; release it now so the child resolver's cache can drain.
        if getattr(self, 'childMemberContainer', None) is not None:
            self.childResolver.Return(self.childMemberContainer)
            self.childMemberContainer = None

        # return the block_store_stream once to match reference counting
        self.resolver.Return(self.block_store_stream)

        return super().__exit__(exc_type, exc_value, traceback)

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
        if self.initial_debug_state is not None and (self.initial_debug_state != self.block_store_stream.DEBUG):
            raise RuntimeError("The debug status of the encrypted stream has been changed after initialization.")
        return self.childContainer


class ZipMemberContainer(MemberContainer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.zip = self.parent
        if self.zip.arn_in_comment is None and len(self.zip.members) > 0:
            self.zip.arn_in_comment = self._arn_from_description()
        if self.zip.arn_in_comment is not None:
            (arn, version, lex) = Container.identifyURNFromZip(self.zip, self.resolver)
            self.urn = rdfvalue.ARN(self.zip.arn_in_comment)
            self.version = version
            self.lex = lex
            self.resolver.addExistingContainer(self)
        else:
            self.zip.arn_in_comment = self.urn
            self.resolver.addNewContainer(self)
        self.children = set()
        self.resolver.ObjectCache.Put(self, True)
        self.Prepare()

    def _arn_from_description(self):
        """The volume ARN from container.description, for zips written without the zip comment."""
        if lexicon.AFF4_CONTAINER_DESCRIPTION not in self.zip.members:
            raise OSError(
                f"{self.zip.urn} is not an AFF4 volume: it has no volume URN in its zip comment"
                f" or in {lexicon.AFF4_CONTAINER_DESCRIPTION}")
        with self.zip.OpenZipSegment(lexicon.AFF4_CONTAINER_DESCRIPTION) as description:
            return description.ReadAll().decode("utf-8").strip()

    def OpenMember(self, arn):
        segment_name = escaping.member_name_for_urn(arn, self.version, self.urn, use_unicode=zip.USE_UNICODE)
        return self.zip.OpenZipSegment(segment_name)

    def CreateMember(self, arn):
        segment_name = escaping.member_name_for_urn(arn, self.version, self.urn, use_unicode=zip.USE_UNICODE)
        return self.zip.CreateZipSegment(segment_name, arn=arn)

    def ContainsMember(self, arn):
        segment_name = escaping.member_name_for_urn(arn, self.version, self.urn, use_unicode=zip.USE_UNICODE)
        return self.zip.ContainsSegment(segment_name)

    def RemoveMember(self, arn):
        segment_name = escaping.member_name_for_urn(arn, self.version, self.urn, use_unicode=zip.USE_UNICODE)
        return self.zip.RemoveSegment(segment_name)

    def RemoveMembers(self, arns):
        for arn in arns:
            segment_name = escaping.member_name_for_urn(arn, self.version, self.urn, use_unicode=zip.USE_UNICODE)
            self.zip.RemoveSegment(segment_name)

    def Close(self):
        pass

    # def __exit__(self, exc_type, exc_value, traceback):
    #     # no caching
    #     # Ensure exceptions aren't silently swallowed (are propagated)
    #     if exc_value is not None:
    #         return False