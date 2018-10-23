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

from pyaff4.utils import SmartStr
from pyaff4 import data_store, aff4_image
from pyaff4 import hashes
from pyaff4 import lexicon
from pyaff4 import aff4_map
from pyaff4 import rdfvalue
from pyaff4 import aff4
from pyaff4 import escaping
from pyaff4.aff4_metadata import RDFObject
from pyaff4 import zip

import yaml
import uuid


localcache = {}

class Image(object):
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
        except:
            pass
    return res


class Container(object):
    def __init__(self, version, volumeURN, resolver, lex):
        self.urn = volumeURN
        self.lexicon = lex
        self.resolver = resolver
        self.version = version

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
    def identifyURN(urn):
        resolver = data_store.MemoryDataStore(lexicon.standard)
        with zip.ZipFile.NewZipFile(resolver, urn) as zip_file:
            if len(list(zip_file.members.keys())) == 0:
                # it's a new zipfile
                raise IOError("Not an AFF4 Volume")
            try:
                # AFF4 Std v1.0 introduced the version file
                version = zip_file.OpenZipSegment("version.txt")
                versionTxt = version.ReadAll()
                resolver.Close(version)
                version = parseProperties(versionTxt)
                return (version, lexicon.standard)
            except:
                if str(resolver.aff4NS) == lexicon.AFF4_NAMESPACE:
                    # Rekall defined the new AFF4 namespace post the Wirespeed paper
                    return ({ "major" : "0", "minor": "0" }, lexicon.scudette)
                else:
                    # Wirespeed (Evimetry) 1.x and Evimetry 2.x stayed with the original namespace
                    return ({ "major" : "0", "minor": "1" }, lexicon.legacy)

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
    def createURN(resolver, container_urn):
        """Public method to create a new writable locical AFF4 container."""

        resolver.Set(container_urn, lexicon.AFF4_STREAM_WRITE_MODE, rdfvalue.XSDString("truncate"))

        zip_file = zip.ZipFile.NewZipFile(resolver, container_urn)

        volume_urn = zip_file.urn
        version = { "major" : "0", "minor": "1", "tool" : "pyaff4" }
        localcache[volume_urn] = WritableLogicalImageContainer(version, volume_urn, resolver, lexicon.standard)
        return localcache[volume_urn]

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

            for stream in datastreams:
                if lex.map in resolver.QuerySubjectPredicate(stream, lexicon.AFF4_TYPE):
                    dataStream = resolver.AFF4FactoryOpen(stream)
                    image = aff4.Image(resolver, urn=imageURN)
                    dataStream.parent = image

                    localcache[urn] = PhysicalImageContainer(volumeURN, resolver, lex, image, dataStream)
                    return localcache[urn]
                

    @staticmethod
    def openURNtoContainer(urn):
        try:
            cached = localcache[urn]
            return cached
        except:
            (version, lex) = Container.identifyURN(urn)
            resolver = data_store.MemoryDataStore(lex)
            with zip.ZipFile.NewZipFile(resolver, urn) as zip_file:
                volumeURN = zip_file.urn
                if lex == lexicon.standard:
                    images = list(resolver.QueryPredicateObject(lexicon.AFF4_TYPE, lex.Image))
                    imageURN = images[0]

                    datastreams = list(resolver.QuerySubjectPredicate(imageURN, lex.dataStream))

                    if len(datastreams) > 0:
                        # it is a disk image or a memory image

                        for stream in datastreams:
                            if lex.map in resolver.QuerySubjectPredicate(stream, lexicon.AFF4_TYPE):
                                dataStream = resolver.AFF4FactoryOpen(stream)
                                image = aff4.Image(resolver, urn=imageURN)
                                dataStream.parent = image

                                localcache[urn] = PhysicalImageContainer(version, volumeURN, resolver, lex, image, dataStream)
                                return localcache[urn]
                    else:
                        # it is a logical image
                        if version["major"] == "1" and version["minor"] == "1":
                            # AFF4 logical images are defined at version 1.1
                            localcache[urn] = LogicalImageContainer(version, volumeURN, resolver, lex)
                            return localcache[urn]
                        else:
                            # scudette's winpmem pre-std implementation is at 1.0
                            lex = lexicon.pmemlogical
                            localcache[urn] = PreStdLogicalImageContainer(version, volumeURN, resolver, lex)
                            return localcache[urn]




                elif lex == lexicon.scudette:
                    m = next(resolver.QueryPredicateObject(lexicon.AFF4_TYPE, lex.map))
                    cat = next(resolver.QuerySubjectPredicate(m, lex.category))
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

                        localcache[urn] = PhysicalImageContainer(version, volumeURN, resolver, lex, image, dataStream)
                        return localcache[urn]

class PhysicalImageContainer(Container):
    def __init__(self, version, volumeURN, resolver, lex, image, dataStream):
        super(PhysicalImageContainer, self).__init__(version, volumeURN, resolver, lex)
        self.image = Image(image, resolver, dataStream)
        self.dataStream = dataStream

class LogicalImageContainer(Container):
    def __init__(self, version, volumeURN, resolver, lex):
        super(LogicalImageContainer, self).__init__(version, volumeURN, resolver, lex)

    def images(self):
        _images = self.resolver.QueryPredicateObject(lexicon.AFF4_TYPE, lexicon.standard11.FileImage)
        for image in _images:
            pathName = next(self.resolver.QuerySubjectPredicate(image, lexicon.standard11.pathName))
            yield aff4.LogicalImage(self.resolver, self.urn, image, pathName)

    def open(self, urn):
        pathName = next(self.resolver.QuerySubjectPredicate(urn, lexicon.standard11.pathName))
        return aff4.LogicalImage(self.resolver, self.urn, urn, pathName)

    def __exit__(self, exc_type, exc_value, traceback):
        # Return ourselves to the resolver cache.
        #self.resolver.Return(self)
        return self

    def __enter__(self):
        return self

class PreStdLogicalImageContainer(LogicalImageContainer):
    def __init__(self, version, volumeURN, resolver, lex):
        super(PreStdLogicalImageContainer, self).__init__(version, volumeURN, resolver, lex)

    def images(self):
        _images = self.resolver.QueryPredicateObject(lexicon.AFF4_TYPE, lexicon.standard.Image)
        for image in _images:
            pathName = next(self.resolver.QuerySubjectPredicate(image, self.lexicon.pathName))
            yield aff4.LogicalImage(self.resolver, self.urn, image, pathName)

    def open(self, urn):
        pathName = next(self.resolver.QuerySubjectPredicate(urn, self.lexicon.pathName))
        return aff4.LogicalImage(self.resolver, self.urn, urn, pathName)

    def __exit__(self, exc_type, exc_value, traceback):
        # Return ourselves to the resolver cache.
        #self.resolver.Return(self)
        return self

    def __enter__(self):
        return self

class WritableLogicalImageContainer(Container):

    # logical images geater than this size are stored in ImageStreams
    # smaller ones in Zip Segments
    maxSegmentResidentSize = 1 * 1024 * 1024

    def __init__(self, version, volumeURN, resolver, lex):
        super(WritableLogicalImageContainer, self).__init__(version, volumeURN, resolver, lex)

        with self.resolver.AFF4FactoryOpen(self.urn) as volume:
            container_description_urn = self.urn.Append("container.description")
            with volume.CreateMember(container_description_urn) as container_description_file:
                container_description_file.Write(SmartStr(volume.urn.value))

            version_urn = self.urn.Append("version.txt")
            with volume.CreateMember(version_urn) as versionFile:
                # AFF4 logical containers are at v1.1
                versionFile.Write(SmartStr(u"major=1\nminor=1\ntool=pyaff4\n"))


    def writeCompressedBlockStream(self, image_urn, filename, readstream):
        with aff4_image.AFF4Image.NewAFF4Image(self.resolver, image_urn, self.urn) as stream:
            stream.compression = lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY
            stream.WriteStream(readstream)

    def writeZipStream(self, image_urn, filename, readstream):
        with self.resolver.AFF4FactoryOpen(self.urn) as volume:
            with volume.CreateMember(image_urn) as streamed:
                streamed.compression_method = zip.ZIP_DEFLATE
                streamed.WriteStream(readstream)


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

        self.resolver.Add(image_urn, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.standard11.FileImage))
        self.resolver.Add(image_urn, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.standard.Image))
        self.resolver.Add(image_urn, rdfvalue.URN(lexicon.standard11.pathName), rdfvalue.XSDString(filename))
        return image_urn

    def isAFF4Collision(self, filename):
        if filename in ["information.turtle", "version.txt", "container.description"]:
            return True
        return False


    def __exit__(self, exc_type, exc_value, traceback):
        # Return ourselves to the resolver cache.
        self.resolver.Return(self)

    def __enter__(self):
        return self