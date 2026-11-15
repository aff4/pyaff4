# Copyright 2016-2018 Schatz Forensic Pty Ltd. All rights reserved.
# Copyright © 2026 Apple Inc.

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
#

import fastcdc
from rdflib import Literal

from pyaff4 import aff4_map
from pyaff4 import aff4_image
from pyaff4 import rdfvalue
from pyaff4 import escaping
from pyaff4 import hashes
from pyaff4 import lexicon
from pyaff4 import container
from pyaff4.rdfvalue import ARN
import uuid
import base64


class WritableHashBasedImageContainer(container.WritableLogicalImageContainer):
    def __init__(self, backing_store, zip_file, version, volumeURN, resolver, lex):
        super().__init__(backing_store, zip_file, version, volumeURN, resolver,
                                                              lex)
        block_store_stream_id = ARN("aff4://%s" % uuid.uuid4())
        with self.resolver.AFF4FactoryOpen(self.urn) as volume:
            self.block_store_stream = aff4_image.AFF4Image.NewAFF4Image(resolver, volume, block_store_stream_id, self.urn)
        self.block_store_stream.compression = lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY

    def preserveChunk(self, logical_file_map, chunk, chunk_offset, chunk_hash, check_bytes):
        # we use RFC rfc4648
        hashid = ARN("aff4:sha512:" + base64.urlsafe_b64encode(chunk_hash.digest()).decode())

        # check if this hash is in the container already
        existing_bytestream_reference_id = self.resolver.GetUnique(lexicon.any, hashid,
                                                                   lexicon.standard.dataStream)

        if existing_bytestream_reference_id is None:
            block_stream_address = self.block_store_stream.TellWrite()
            self.block_store_stream.Write(chunk)

            chunk_reference_id = self.block_store_stream.urn + "[0x%x:0x%x]" % (
                block_stream_address, len(chunk))
            self.resolver.Add(self.urn, hashid, lexicon.standard.dataStream, chunk_reference_id)

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

                        chunk_reference_id = self.block_store_stream.urn + "[0x%x:0x%x]" % (
                            block_stream_address, len(chunk))
                        logical_file_map.AddRange(chunk_offset, block_stream_address, len(chunk),
                                                  self.block_store_stream.urn)

                        self.resolver.Add(self.urn, hashid, lexicon.standard11.collidingDataStream,
                                          chunk_reference_id)
                    else:
                        logical_file_map.AddRange(chunk_offset, 0, len(chunk), hashid)
            else:
                logical_file_map.AddRange(chunk_offset, 0, len(chunk), hashid)

    def writeLogicalStreamHashBased(self, filename, readstream, length, check_bytes=False):
        logical_file_id = None
        if self.isAFF4Collision(filename):
            logical_file_id = ARN("aff4://%s" % uuid.uuid4())
        else:
            logical_file_id = self.urn.Append(escaping.arnPathFragment_from_path(filename), quote=False)

        chunk_size = self.block_store_stream.chunk_size

        with self.resolver.AFF4FactoryOpen(self.urn) as volume:
            with aff4_map.AFF4Map.NewAFF4Map(
                    self.resolver, volume, logical_file_id, self.urn) as logical_file_map:
                file_offset = 0
                while file_offset < length:
                    toread = min(length - file_offset, chunk_size)
                    chunk = readstream.read(toread)

                    # pad the chunk to chunksize if it is small
                    read_chunk_size = len(chunk)
                    if read_chunk_size < chunk_size:
                        chunk = chunk + b"\x00" * (chunk_size - read_chunk_size)

                    h = hashes.new(lexicon.HASH_SHA512)
                    h.update(chunk)
                    # we use RFC rfc4648
                    hashid = ARN("aff4:sha512:" + base64.urlsafe_b64encode(h.digest()).decode())

                    # check if this hash is in the container already
                    existing_bytestream_reference_id = self.resolver.GetUnique(lexicon.any, hashid,
                                                                               lexicon.standard.dataStream)

                    if existing_bytestream_reference_id is None:
                        block_stream_address = self.block_store_stream.TellWrite()
                        self.block_store_stream.Write(chunk)

                        chunk_reference_id = self.block_store_stream.urn + "[0x%x:0x%x]" % (block_stream_address, chunk_size)
                        self.resolver.Add(self.urn, hashid, lexicon.standard.dataStream, chunk_reference_id)

                        logical_file_map.AddRange(file_offset, 0, toread, hashid)
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

                                    chunk_reference_id = self.block_store_stream.urn + "[0x%x:0x%x]" % (
                                        block_stream_address, chunk_size)
                                    logical_file_map.AddRange(file_offset, block_stream_address, chunk_size,
                                                              self.block_store_stream.urn)

                                    self.resolver.Add(self.urn, hashid,
                                                      lexicon.standard11.collidingDataStream,
                                                      chunk_reference_id)
                                else:
                                    logical_file_map.AddRange(file_offset, 0, toread, hashid)
                        else:
                            logical_file_map.AddRange(file_offset, 0, toread, hashid)
                        # print("[%x, %x] -> %s -> %s" % (file_offset, toread, hashid, existing_bytestream_reference_id))

                    file_offset += toread

        logical_file_map.Close()

        self.resolver.Add(self.urn, logical_file_id, lexicon.AFF4_TYPE,
                          lexicon.standard11.FileImage)
        self.resolver.Add(self.urn, logical_file_id, lexicon.AFF4_TYPE,
                          lexicon.standard.Image)
        self.resolver.Add(self.urn, logical_file_id, lexicon.standard11.pathName,
                          Literal(filename))
        return logical_file_id

    def __exit__(self, exc_type, exc_value, traceback):
        # Return ourselves to the resolver cache.
        self.resolver.Return(self.block_store_stream)
        return super().__exit__(exc_type, exc_value, traceback)

    def writeLogicalStreamRabinHashBased(self, filename, readstream, length, check_bytes=False):
        # Note: despite the historical name, this uses FastCDC for
        # content-defined chunking (fastchunking's Rabin-Karp
        # implementation no longer builds on current macOS SDKs).
        logical_file_id = None
        if self.isAFF4Collision(filename):
            logical_file_id = ARN("aff4://%s" % uuid.uuid4())
        else:
            logical_file_id = self.urn + escaping.arnPathFragment_from_path(filename)

        data = readstream.read(length)

        with self.resolver.AFF4FactoryOpen(self.urn) as volume:
            with aff4_map.AFF4Map.NewAFF4Map(
                    self.resolver, volume, logical_file_id, self.urn) as logical_file_map:
                for chunk in fastcdc.fastcdc(data, avg_size=4096, fat=True):
                    h = hashes.new(lexicon.HASH_SHA512)
                    h.update(chunk.data)
                    self.preserveChunk(
                        logical_file_map, chunk.data, chunk.offset, h, check_bytes)

        logical_file_map.Close()

        self.resolver.Add(self.urn, logical_file_id, lexicon.AFF4_TYPE,
                          lexicon.standard11.FileImage)
        self.resolver.Add(self.urn, logical_file_id, lexicon.AFF4_TYPE,
                          lexicon.standard.Image)
        self.resolver.Add(self.urn, logical_file_id, lexicon.standard11.pathName,
                          Literal(filename))
        return logical_file_id
