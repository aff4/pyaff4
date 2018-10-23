from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals
# Copyright 2016,2017 Schatz Forensic Pty Ltd. All rights reserved.
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

from pyaff4 import data_store
from pyaff4 import hashes
from pyaff4 import lexicon
from pyaff4 import aff4_map
from pyaff4 import rdfvalue
from pyaff4 import aff4
from pyaff4.aff4_metadata import RDFObject

import yaml
from pyaff4 import zip

localcache = {}

class Image(object):
    def __init__(self, image, resolver, dataStream):
        self.image = image
        self.urn = image.urn
        self.resolver = resolver
        self.dataStream = dataStream

class Container(object):
    def __init__(self, volumeURN, resolver, lex, image, dataStream):
        self.urn = volumeURN
        self.lexicon = lex
        self.resolver = resolver
        self.image = Image(image, resolver, dataStream)
        self.dataStream = dataStream

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
                resolver.Close(version)
                return lexicon.standard
            except:
                if str(resolver.aff4NS) == lexicon.AFF4_NAMESPACE:
                    # Rekall defined the new AFF4 namespace post the Wirespeed paper
                    return lexicon.scudette
                else:
                    # Wirespeed (Evimetry) 1.x and Evimetry 2.x stayed with the original namespace
                    return lexicon.legacy

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
    def openURN(urn):
        return Container.openURNtoContainer(urn).image.dataStream

    @staticmethod
    def openURNtoContainer(urn):
        try:
            cached = localcache[urn]
            return cached
        except:
            lex = Container.identifyURN(urn)
            resolver = data_store.MemoryDataStore(lex)
            with zip.ZipFile.NewZipFile(resolver, urn) as zip_file:
                volumeURN = zip_file.urn
                if lex == lexicon.standard:
                    imageURN = next(resolver.QueryPredicateObject(lexicon.AFF4_TYPE, lex.Image))

                    datastreams = list(resolver.QuerySubjectPredicate(imageURN, lex.dataStream))

                    for stream in datastreams:
                        if lex.map in resolver.QuerySubjectPredicate(stream, lexicon.AFF4_TYPE):
                            dataStream = resolver.AFF4FactoryOpen(stream)
                            image = aff4.Image(resolver, urn=imageURN)
                            dataStream.parent = image

                            localcache[urn] = Container(volumeURN, resolver, lex, image, dataStream)
                            return localcache[urn]

                elif lex == lexicon.scudette:
                    m = next(resolver.QueryPredicateObject(lexicon.AFF4_TYPE, lex.map))
                    cat = next(resolver.QuerySubjectPredicate(m, lex.category))
                    if cat == lex.memoryPhysical:
                        dataStream = resolver.AFF4FactoryOpen(m)

                        image = aff4.Image(resolver, urn=m)
                        dataStream.parent = image

                        legacyYamlInfoURI = dataStream.urn.Append("information.yaml")
                        with resolver.AFF4FactoryOpen(legacyYamlInfoURI) as fd:
                            txt = fd.read(10000000)
                            dt = yaml.safe_load(txt)
                            try:
                                CR3 = dt["Registers"]["CR3"]
                                resolver.Add(dataStream.parent.urn, lexicon.standard.memoryPageTableEntryOffset, rdfvalue.XSDInteger(CR3))
                                kaslr_slide = dt["kaslr_slide"]
                                resolver.Add(dataStream.parent.urn, lexicon.standard.OSXKALSRSlide,
                                             rdfvalue.XSDInteger(kaslr_slide))

                            except:
                                pass
                        localcache[urn] = Container(volumeURN, resolver, lex, image, dataStream)
                        return localcache[urn]