# Copyright 2016,2017 Schatz Forensic Pty Ltd. All rights reserved.
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

import io

from rdflib import Literal

from pyaff4 import aff4
from pyaff4 import block_hasher
from pyaff4 import container
from pyaff4 import data_store
from pyaff4 import hashes
from pyaff4 import lexicon
from pyaff4 import zip


class LinearHasher:
    def __init__(self, listener=None):
        if listener is None:
            self.listener = block_hasher.ValidationListener()
        else:
            self.listener = listener
        self.delegate = None

    def hash(self, urn, mapURI, hashDataType):
        resolver = data_store.MemoryDataStore(lexicon.standard)

        # Open zip once and identify against the open instance instead of
        # calling identifyURN first (which would open, parse, then close the
        # zip — incurring a second load when NewZipFile reopens it below).
        with zip.ZipFile.NewZipFile(resolver, None, urn) as zip_file:
            (arn, version, lex) = container.Container.identifyURNFromZip(zip_file, resolver=resolver)
            resolver.lexicon = lex
            # The streamFactory is keyed off the lexicon so update it now
            # that we know the actual lexicon for this container.
            if lex == lexicon.legacy:
                from pyaff4 import stream_factory
                resolver.streamFactory = stream_factory.PreStdStreamFactory(resolver, lex)
            zip_file.version = version
            with container.ZipMemberContainer(resolver, None, zip_file, version=version) as member_container:
                if lex == lexicon.standard:
                    self.delegate = InterimStdLinearHasher(resolver, lex, self.listener)
                elif lex == lexicon.legacy:
                    self.delegate = PreStdLinearHasher(resolver, lex, self.listener)
                elif lex == lexicon.scudette:
                    self.delegate = ScudetteLinearHasher(resolver, lex, self.listener)
                else:
                    raise ValueError

                self.delegate.volume_arn = member_container.urn
                return self.delegate.doHash(mapURI, hashDataType)

    def hashMulti(self, urna, urnb, mapURI, hashDataType):
        resolver = data_store.MemoryDataStore(lexicon.standard)

        with zip.ZipFile.NewZipFile(resolver, None, urna) as zip_filea:
            (arn, version, lex) = container.Container.identifyURNFromZip(zip_filea, resolver=resolver)
            resolver.lexicon = lex
            if lex == lexicon.legacy:
                from pyaff4 import stream_factory
                resolver.streamFactory = stream_factory.PreStdStreamFactory(resolver, lex)
            zip_filea.version = version
            with container.ZipMemberContainer(resolver, None, zip_filea, version=version) as mca:
                with zip.ZipFile.NewZipFile(resolver, version, urnb) as zip_fileb:
                    with container.ZipMemberContainer(resolver, None, zip_fileb, version=version) as mcb:
                        if lex == lexicon.standard:
                            self.delegate = InterimStdLinearHasher(resolver, lex, self.listener)
                        elif lex == lexicon.legacy:
                            self.delegate = PreStdLinearHasher(resolver, lex, self.listener)
                        else:
                            raise ValueError

                        self.delegate.volume_arn = mca.urn
                        return self.delegate.doHash(mapURI, hashDataType)

    def doHash(self, mapURI, hashDataType):
        hash = hashes.new(hashDataType)

        if self.isMap(mapURI):
            with self.resolver.AFF4FactoryOpen(mapURI) as mapStream:
                remaining = mapStream.Size()
                count = 0
                while remaining > 0:
                    toRead = min(32*1024, remaining)
                    data = mapStream.Read(toRead)
                    assert len(data) == toRead
                    remaining -= len(data)
                    hash.update(data)
                    count = count + 1

                b = hash.hexdigest()
                #return hashes.newImmutableHash(b, hashDataType)
                return Literal(b, datatype=hashDataType)
        raise Exception("IllegalState")

    def isMap(self, stream):
        for type in self.resolver.QuerySubjectPredicate(self.volume_arn, stream, lexicon.AFF4_TYPE):
            if self.lexicon.map == type:
                return True

        return False


class PreStdLinearHasher(LinearHasher):
    def __init__(self, resolver, lex, listener=None):
        LinearHasher.__init__(self, listener)
        self.lexicon = lex
        self.resolver = resolver


class InterimStdLinearHasher(LinearHasher):
    def __init__(self, resolver, lex, listener=None):
        LinearHasher.__init__(self, listener)
        self.lexicon = lex
        self.resolver = resolver


class ScudetteLinearHasher(LinearHasher):
    def __init__(self, resolver, lex, listener=None):
        LinearHasher.__init__(self, listener)
        self.lexicon = lex
        self.resolver = resolver

class LinearHasher2:
    def __init__(self, resolver, listener=None):
        if listener is None:
            self.listener = block_hasher.ValidationListener()
        else:
            self.listener = listener
        self.delegate = None
        self.resolver = resolver

    def hash(self, image, progress=None):

        storedHashes = list(self.resolver.QuerySubjectPredicate(image.container.urn, image.urn, lexicon.standard.hash))
        with self.resolver.AFF4FactoryOpen(image.urn, version=image.container.version) as stream:
            datatypes = [h.datatype for h in storedHashes]
            stream2 = StreamHasher(stream, datatypes)
            self.readall2(stream2, progress=progress)
            for storedHash in storedHashes:
                dt = storedHash.datatype
                shortHashAlgoName = hashes.shortName(dt)
                calculatedHashHexDigest = stream2.getHash(dt).hexdigest()
                storedHashHexDigest = storedHash.toPython()
                if storedHashHexDigest == calculatedHashHexDigest:
                    self.listener.onValidHash(shortHashAlgoName, calculatedHashHexDigest, image.urn)
                else:
                    self.listener.onInvalidHash(shortHashAlgoName, storedHashHexDigest, calculatedHashHexDigest, image.urn)


    def readall2(self, stream, progress=None):
        if progress is None:
            progress = aff4.EMPTY_PROGRESS
        total_read = 0
        while True:
            toRead = 32 * 1024
            data = stream.read(toRead)
            if data is None or len(data) == 0:
                # EOF
                return
            total_read += len(data)
            progress.Report(total_read)


class StreamHasher:
    def __init__(self, parent, hashDatatypes):
        self.parent = parent
        self.hashes = []
        self.hashToType = {}
        for hashDataType in hashDatatypes:
            h = hashes.new(hashDataType)
            self.hashToType[h] = hashDataType
            self.hashes.append(h)

    def read(self, bytes):
        data = self.parent.read(bytes)
        datalen = len(data)
        if datalen > 0:
            for h in self.hashes:
                h.update(data)
        return data

    def getHash(self, dataType):
        return next(h for h in self.hashes if self.hashToType[h] == dataType)

class PushHasher:
    def __init__(self, hashDatatypes):
        self.hashes = []
        self.hashToType = {}
        for hashDataType in hashDatatypes:
            h = hashes.new(hashDataType)
            self.hashToType[h] = hashDataType
            self.hashes.append(h)

    def update(self, data):
        datalen = len(data)
        if datalen > 0:
            for h in self.hashes:
                h.update(data)

    def getHash(self, dataType):
        return next(h for h in self.hashes if self.hashToType[h] == dataType)