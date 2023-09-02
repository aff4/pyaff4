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

from builtins import object
import io
from pyaff4 import block_hasher
from pyaff4 import container
from pyaff4 import data_store
from pyaff4 import hashes
from pyaff4 import lexicon
from pyaff4 import zip
from pyaff4 import aff4


class LinearHasher(object):
    def __init__(self, listener=None):
        if listener == None:
            self.listener = block_hasher.ValidationListener()
        else:
            self.listener = listener
        self.delegate = None

    def hash(self, urn, mapURI, hashDataType):
        (version, lex) = container.Container.identifyURN(urn)
        resolver = data_store.MemoryDataStore(lex)

        with zip.ZipFile.NewZipFile(resolver, version, urn) as zip_file:
            if lex == lexicon.standard:
                self.delegate = InterimStdLinearHasher(resolver, lex, self.listener)
            elif lex == lexicon.legacy:
                self.delegate = PreStdLinearHasher(resolver, lex, self.listener)
            elif lex == lexicon.scudette:
                self.delegate = ScudetteLinearHasher(resolver, lex, self.listener)
            else:
                raise ValueError

            self.delegate.volume_arn = zip_file.urn
            return self.delegate.doHash(mapURI, hashDataType)

    def hashMulti(self, urna, urnb, mapURI, hashDataType):
        (version, lex) = container.Container.identifyURN(urna)
        resolver = data_store.MemoryDataStore(lex)

        with zip.ZipFile.NewZipFile(resolver, version, urna) as zip_filea:
            with zip.ZipFile.NewZipFile(resolver, version, urnb) as zip_fileb:
                if lex == lexicon.standard:
                    self.delegate = InterimStdLinearHasher(resolver, lex, self.listener)
                elif lex == lexicon.legacy:
                    self.delegate = PreStdLinearHasher(resolver, lex, self.listener)
                else:
                    raise ValueError

                self.delegate.volume_arn = zip_filea.urn
                return self.delegate.doHash(mapURI, hashDataType)

    def doHash(self, mapURI, hashDataType):
        hash = hashes.new(hashDataType)
        if not self.isMap(mapURI):
            import pdb; pdb.set_trace()

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
                return hashes.newImmutableHash(b, hashDataType)
        raise Exception("IllegalState")

    def doHash(self, mapURI, hashDataType):
        hash = hashes.new(hashDataType)
        if not self.isMap(mapURI):
            import pdb; pdb.set_trace()

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
                return hashes.newImmutableHash(b, hashDataType)
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
        if listener == None:
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
                shortHashAlgoName = storedHash.shortName()
                calculatedHashHexDigest = stream2.getHash(dt).hexdigest()
                storedHashHexDigest = storedHash.value
                if storedHashHexDigest == calculatedHashHexDigest:
                    self.listener.onValidHash(shortHashAlgoName, calculatedHashHexDigest, image.urn)
                else:
                    self.listener.onInvalidHash(shortHashAlgoName, storedHashHexDigest, calculatedHashHexDigest, image.urn)


    def readall2(self, stream, progress=None):
        total_read = 0
        if progress is None:
            progress = aff4.EMPTY_PROGRESS
        while True:
            toRead = 32 * 1024
            data = stream.read(toRead)
            total_read += len(data)
            progress.Report(total_read)
            if data == None or len(data) == 0:
                # EOF
                return


class StreamHasher(object):
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

class PushHasher(object):
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