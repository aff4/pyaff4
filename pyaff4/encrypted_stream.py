# Copyright 2019 Schatz Forensic Pty Ltd All rights reserved.
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
#
# Author: Bradley L Schatz bradley@evimetry.com

"""This module implements the standard AFF4 Image."""
from __future__ import division
from __future__ import unicode_literals
from builtins import range
from builtins import str
from past.utils import old_div
from builtins import object
import binascii
import logging
import struct
import math
from CryptoPlus.Cipher import python_AES

from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import registry
from pyaff4 import  hexdump
from pyaff4.aff4_image import  AFF4SImage


LOGGER = logging.getLogger("pyaff4")
DEBUG = False

class RandomImageStream(AFF4SImage):
    def FlushChunk(self, chunk):
        if len(chunk) == 0:
            return

        bevy_offset = self.chunk_count_in_bevy * self.chunk_size

        compressed_chunk = chunk

        compressedLen = len(compressed_chunk)

        bufToWrite = b''
        lenToWrite = -1

        if compressedLen < self.chunk_size - 16:
            bufToWrite = compressed_chunk
            lenToWrite = compressedLen
        else:
            bufToWrite = chunk
            lenToWrite = self.chunk_size

        if self.chunk_count_in_bevy < len(self.bevy):
            self.bevy_index[self.chunk_count_in_bevy] = (bevy_offset, lenToWrite)
            self.bevy[self.chunk_count_in_bevy] = bufToWrite
        else:
            self.bevy_index.append((bevy_offset, lenToWrite))
            self.bevy.append(bufToWrite)
            self.bevy_length += 1
            if self.bevy_size_has_changed == False:
                self.bevy_size_has_changed = True

        self.chunk_count_in_bevy += 1
        self.currentLCA += 1

    def IsFull(self):
        return self.chunk_count_in_bevy >= self.chunks_per_segment and len(self.buffer) > 0

    def padToChunksize(self, buf):
        padding = self.chunk_size - len(buf)
        if padding == 0:
            return buf
        else :
            return buf + b'\0' * padding

    def flushCurrentChunk(self):
        self.FlushChunk(self.padToChunksize(self.buffer))
        self.buffer = b''

    def flushCurrentChunkAndBevy(self):
        if len(self.buffer) > 0:
            self.FlushChunk(self.padToChunksize(self.buffer))
            self.buffer = b''
        for i in range(self.chunk_count_in_bevy, self.chunks_per_segment):
            if i >= len(self.bevy):
                # for chunks with no storage we zero fill
                self.FlushChunk(b'\0' * self.chunk_size)
        self._FlushBevy()

    def lcaToBC(self, lca):
        bevyIdx = lca // self.chunks_per_segment
        chunkIdx = lca % self.chunks_per_segment
        return (bevyIdx, chunkIdx)

    def loadChunkFromBevy(self, chunkIdx):
        self.chunk_count_in_bevy = chunkIdx
        if chunkIdx >= len(self.bevy):
            self.buffer = b''
        else:
            self.buffer = self.bevy[chunkIdx]
        self.currentLCA = self.chunks_per_segment * self.bevy_number + chunkIdx

    def Trim(self, offset):
        assert offset < self.size
        self.writeptr = offset
        self.size = offset

    def Write(self, data):
        wrote = 0
        totalWrote = 0

        if wrote > 0:
            self.writeptr += wrote

        toWrite = len(data)
        if toWrite == 0:
            return 0

        self.MarkDirty()
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug("EncryptedStream::Write %x[%x]" % (self.writeptr, len(data)))
        #hexdump.hexdump(data)


        targetLCA = self.writeptr // self.chunk_size

        #if self.IsFull():
        #    self._FlushBevy()

        if self.currentLCA != targetLCA:
            if self.currentLCA > targetLCA:
                currentBevyStart = self.currentLCA // self.chunks_per_segment
                (targetBevyIdx, targetChunkIdx) = self.lcaToBC(targetLCA)
                if currentBevyStart == targetBevyIdx:
                    # this write is in the same bevy. We flush the current chunk if we have
                    # writes cached and then reaload the new chunk from the bevy
                    if len(self.buffer) > 0:
                        self.FlushChunk(self.buffer)
                    self.loadChunkFromBevy(targetChunkIdx)
                else:
                    # writes are to a different bevy. If the current open bevy has storage then flush it
                    # Then load the bevy and chunk
                    if len(self.buffer) > 0 or len(self.bevy) > 0:
                        self.flushCurrentChunkAndBevy()
                    self.reloadBevy(targetBevyIdx)
                    self.loadChunkFromBevy(targetChunkIdx)
            else:  # self.currentLCA < targetLCA:
                if self.bevy_number <= self.maxBevyIdx:
                    (targetBevyIdx, targetChunkIdx) = self.lcaToBC(targetLCA)
                    if self.bevy_number == targetBevyIdx:
                        self.flushCurrentChunk()
                        self.loadChunkFromBevy(targetChunkIdx)
                    else:
                        self.flushCurrentChunkAndBevy()
                        if targetBevyIdx <= self.maxBevyIdx:
                            self.reloadBevy(targetBevyIdx)
                            self.loadChunkFromBevy(targetChunkIdx)
                else:
                    self.flushCurrentChunkAndBevy()
                    # allocate bevvys up to the new bevy
                    for i in range(self.currentLCA, targetLCA):
                        self.FlushChunk(b'\0' * self.chunk_size)
                        if self.IsFull():
                            self._FlushBevy()
                    self.size = self.currentLCA * self.chunk_size

        chunkStartAddress = (self.chunk_count_in_bevy + (
                    self.bevy_number * self.chunks_per_segment)) * self.chunk_size
        bevyStartAddress = (self.bevy_number * self.chunks_per_segment) * self.chunk_size
        offsetInChunk = self.writeptr - chunkStartAddress

        if self.writeptr == self.size and len(self.buffer) == offsetInChunk:
            self.buffer += data
            wrote = len(data)

        elif self.writeptr >= chunkStartAddress:
            # overwrite within the current chunk
            if len(self.buffer) < offsetInChunk:
                firstPiece = b'\0' * offsetInChunk
            else:
                firstPiece = self.buffer[0:offsetInChunk]

            if offsetInChunk + len(data) < len(self.buffer):
                lastPiece = self.buffer[offsetInChunk + len(data):]
                self.buffer = firstPiece + data + lastPiece
            else:
                # full overwrite of the remainder of the buffer
                self.buffer = firstPiece + data
        else:
            raise RuntimeError("Illegal state.")


        idx = 0
        #chunksToWrite = math.ceil(len(self.buffer) / self.chunk_size)
        chunksToWrite = len(self.buffer) // self.chunk_size
        remainderToWrite = len(self.buffer) % self.chunk_size

        if chunksToWrite > 1  or ( chunksToWrite == 1 and remainderToWrite > 0):
            # only do this if the write changed chunks outside the current one.
            # i.e. we will have leftover in the buffer, or need to flush more than one
            # chunk from the buffer to the bevy
            startLCA = self.currentLCA
            endLCA = startLCA + chunksToWrite
            for targetLCA in range(startLCA, endLCA):
                flushed = False
                if self.chunk_count_in_bevy == self.chunks_per_segment:
                    # full bevvy
                    self._FlushBevy()
                    flushed = True

                if self.chunk_count_in_bevy == 0 and flushed:
                    # start of bevy
                    if chunksToWrite >= self.chunks_per_segment:
                        # writing a full bevvy - no need to load the bevy
                        pass
                    else:
                        if self.bevy_number <= self.maxBevyIdx:
                            self.reloadBevy(self.bevy_number)
                        else:
                            #writing into a new bevvy at eof
                            pass

                if idx + self.chunk_size <= len(self.buffer):
                    chunk = self.buffer[idx:idx + self.chunk_size]
                    idx += self.chunk_size
                    chunksToWrite -= 1
                    self.FlushChunk(chunk)


        # if the bevy is full and there is no remainder, flush it
        if self.chunk_count_in_bevy == self.chunks_per_segment:
            self._FlushBevy()
            # if the following bevy is persisted, load it from storage
            if self.bevy_number <= self.maxBevyIdx:
                self.reloadBevy(self.bevy_number)

        # deal with the partial remainder if it exists
        if idx > 0:
            remainderBuf = self.buffer[idx:]
            if len(remainderBuf) > 0:
                self.buffer = self.mergeBufferWithChunk(remainderBuf)

        wrote = len(data)
        self.writeptr += wrote
        totalWrote += wrote
        if self.writeptr > self.size:
            self.size = self.writeptr
        return totalWrote

    def mergeBufferWithChunk(self, buf):
        assert len(buf) <= self.chunk_size

        if self.chunk_count_in_bevy >= len(self.bevy):
            return buf
        else:
            chunk = self.bevy[self.chunk_count_in_bevy]
            #assert len(chunk) == self.chunk_size
            if len(buf) == 0:
                return chunk
            joinPoint = len(buf)
            end = chunk[joinPoint:]
            return  buf + end

    # hook for decryption
    def onChunkLoad(self, chunk, bevy_index, chunk_index):
        return chunk

    def LoadFromURN(self):
        self.currentLCA = 0
        self.maxBevyIdx = 0
        self.bevy_is_loaded_from_disk = False
        super(RandomImageStream, self).LoadFromURN()
        if self.size > 0:
            self.loadInitialBevy()
            self.maxBevyIdx = math.ceil(self.size / (self.chunk_size*self.chunks_per_segment)) -1

    # extension point so that for this class we load the initial bevy on load
    # the encryption oriented subclass NOOP overrides this to defer the initialization to
    # after the set of the keys
    def loadInitialBevy(self):
        self.doLoadInitialBevy()

    def doLoadInitialBevy(self):
        self.reloadBevy(0)
        self.bevy_is_loaded_from_disk = True
        self.buffer = self.bevy[0]

    def _FlushBevy(self):
        if LOGGER.isEnabledFor(logging.INFO):
            LOGGER.info("Flushing Bevy id=%x, entries=%x", self.bevy_number, len(self.bevy_index))
        # Bevy is empty nothing to do.
        if not self.bevy:
            return

        volume_urn = self.resolver.GetUnique(lexicon.transient_graph, self.urn, lexicon.AFF4_STORED)
        if not volume_urn:
            raise IOError("Unable to find storage for urn %s" % self.urn)
        
        if self.bevy_number > self.maxBevyIdx:
            self.maxBevyIdx = self.bevy_number
        if len(self.bevy) > self.bevy_length or self.bevy_size_has_changed:
            volume_urn = self.resolver.GetUnique(lexicon.transient_graph, self.urn, lexicon.AFF4_STORED)
            with self.resolver.AFF4FactoryOpen(volume_urn, version=self.version) as volume:
                bevy_urn = self.urn.Append("%08d" % self.bevy_number)
                bevy_index_urn = rdfvalue.URN("%s.index" % bevy_urn)
                #if self.bevy_is_loaded_from_disk:
                if LOGGER.isEnabledFor(logging.INFO):
                    ("Removing bevy member %s", bevy_urn)
                volume.RemoveMember(bevy_urn)
                if LOGGER.isEnabledFor(logging.INFO):
                    LOGGER.info("Removing bevy member %s", bevy_index_urn)
                volume.RemoveMember(bevy_index_urn)

        bevy_urn = self.urn.Append("%08d" % self.bevy_number)
        with self.resolver.AFF4FactoryOpen(volume_urn) as volume:
            self._write_bevy_index(volume, bevy_urn, self.bevy_index, flush=True)

            with volume.CreateMember(bevy_urn) as bevy:
                content = b"".join(self.bevy)
                if LOGGER.isEnabledFor(logging.INFO):
                    LOGGER.info("Writing Bevy Content len=%x", len(content))
                bevy.Write(content)
                if self.bevy_is_loaded_from_disk and not self.bevy_size_has_changed:
                    # no need to rewrite the bevy as the zip header is still good
                    # and the blocks have been rewritten in-place
                    bevy._dirty = False

            # We dont need to hold these in memory any more.
            self.resolver.Close(bevy)

        # In Python it is more efficient to keep a list of chunks and then join
        # them at the end in one operation.
        self.chunk_count_in_bevy = 0
        self.bevy_number += 1
        self.bevy = []
        self.bevy_index = []
        self.bevy_length = 0
        self.bevy_is_loaded_from_disk = False
        self.bevy_size_has_changed = False

    def Flush(self):
        if self.IsDirty():
            if len(self.buffer) == 0:
                pass
            else:
                if self.chunk_count_in_bevy < len(self.bevy):
                    if len(self.buffer) < self.chunk_size:
                        # merge the buffer into the chunk
                        offset = len(self.buffer)
                        buf = self.buffer + self.bevy[self.chunk_count_in_bevy][offset:]
                        self.FlushChunk(buf)
                    else:
                        l=  len(self.buffer)
                        assert l == self.chunk_size
                        self.FlushChunk(self.buffer)
                else:
                    if self.chunk_count_in_bevy == self.chunks_per_segment:
                        # its a full bevvy and the buffer should be invalid
                        assert len(self.buffer) == 0
                    else:
                        # we dont have a bevvy entry for the buffer yet
                        self.FlushChunk(self.padToChunksize(self.buffer))

            self._FlushBevy()

            self._write_metadata()
        self._dirty = False

    def dump(self):
        if len(self.bevy) == 0:
            hexdump.hexdump(self.buffer)
        else:
            for i in range(0, len(self.bevy)):
                if i == self.chunk_count_in_bevy:
                    hexdump.hexdump(self.buffer)
                else:
                    hexdump.hexdump(self.bevy[i])


class AFF4EncryptedStream(RandomImageStream):
    DEBUG = False
    compression = lexicon.AFF4_IMAGE_COMPRESSION_STORED
    def LoadFromURN(self):
        super(AFF4EncryptedStream, self).LoadFromURN()
        volume_urn = self.resolver.GetUnique(lexicon.transient_graph, self.urn, lexicon.AFF4_STORED)
        storedChunksize = self.resolver.GetUnique(volume_urn, self.urn, self.lexicon.chunkSize)

        if storedChunksize == None:
            # initializing so setup the proper (non-debug chunksize)
            self.chunk_size = 512
            self.DEBUG = False
        else:
            if self.chunk_size != 512:
                self.DEBUG = True
        self.keybags = []

    def setKeyBag(self, kb):
        self.keybags = [kb]

    def addKeyBag(self, kb):
        self.keybags.append(kb)

    def setKey(self, vek):
        self.vek = vek
        self.key1 = vek[0:16]
        self.key2 = vek[16:]
        self.cipher = python_AES.new((self.key1, self.key2), python_AES.MODE_XTS)
        if self.size > 0:
            self.doLoadInitialBevy()

    def loadInitialBevy(self):
        # dont load the initial bevy info if the key isnt set
        pass

    def Flush(self):
        super(AFF4EncryptedStream, self).Flush()

    def _FlushBevy(self):
        # Bevy is empty nothing to do.
        if not self.bevy:
            return

        if self.bevy_number > self.maxBevyIdx:
            self.maxBevyIdx = self.bevy_number

        volume_urn = self.resolver.GetUnique(lexicon.transient_graph, self.urn, lexicon.AFF4_STORED)
        if not volume_urn:
            raise IOError("Unable to find storage for urn %s" % self.urn)

        if len(self.bevy) > self.bevy_length or self.bevy_size_has_changed:
            with self.resolver.AFF4FactoryOpen(volume_urn, version=self.version) as volume:
                bevy_urn = self.urn.Append("%08d" % self.bevy_number)
                bevy_index_urn = rdfvalue.URN("%s.index" % bevy_urn)
                #if self.bevy_is_loaded_from_disk:
                volume.RemoveMember(bevy_urn)
                volume.RemoveMember(bevy_index_urn)

        lastChunkIdx = len(self.bevy)-1
        lastChunk = self.bevy[lastChunkIdx]
        if len(lastChunk) < self.chunk_size:
            self.bevy[lastChunkIdx] = lastChunk + b'\0' * (self.chunk_size - len(lastChunk))
            (bevy_offset, lenToWrite) = self.bevy_index[lastChunkIdx]
            self.bevy_index[lastChunkIdx] = (bevy_offset, self.chunk_size)

        bevy_urn = self.urn.Append("%08d" % self.bevy_number)
        with self.resolver.AFF4FactoryOpen(volume_urn) as volume:
            self._write_bevy_index(volume, bevy_urn, self.bevy_index, flush=True)
            encryptedBevys = []

            with volume.CreateMember(bevy_urn) as bevy:
                for chunkIdx in range(0,len(self.bevy)):
                    chunk_address = self.bevy_number * self.chunks_per_segment + chunkIdx
                    tweak = struct.pack("<Q", chunk_address)

                    if self.DEBUG:
                        encryptedBevys.append(self.bevy[chunkIdx])
                    else:
                        encryptedBevys.append(self.cipher.encrypt(self.bevy[chunkIdx], tweak))
                buf = b"".join(encryptedBevys)
                bevy.Write(buf)
                if self.bevy_is_loaded_from_disk and not self.bevy_size_has_changed:
                    # no need to rewrite the bevy as the zip header is still good
                    # and the blocks have been rewritten in-place
                    bevy._dirty = False

            # We dont need to hold these in memory any more.
            self.resolver.Close(bevy)

        # In Python it is more efficient to keep a list of chunks and then join
        # them at the end in one operation.
        self.chunk_count_in_bevy = 0
        self.bevy_number += 1
        self.bevy = []
        self.bevy_index = []
        self.bevy_length = 0
        self.bevy_is_loaded_from_disk = False
        self.bevy_size_has_changed = False

    def onChunkLoad(self, chunk, bevy_index, chunk_index):
        chunk_id = bevy_index * self.chunks_per_segment + chunk_index
        return self.doDecompress(chunk, chunk_id)

    def doDecompress(self, cbuffer, chunk_id):
        if self.DEBUG:
            return cbuffer

        unit_number = chunk_id
        tweak = struct.pack("<Q", unit_number)

        cipher = python_AES.new((self.key1,self.key2), python_AES.MODE_XTS)
        plaintext = cipher.decrypt(cbuffer, tweak)

        return plaintext

    def _write_metadata(self):
        volume_urn = self.resolver.GetUnique(lexicon.transient_graph, self.urn, lexicon.AFF4_STORED)
        self.resolver.Add(volume_urn, self.urn, lexicon.AFF4_TYPE,
                          rdfvalue.URN(lexicon.AFF4_ENCRYPTEDSTREAM_TYPE))

        self.resolver.Set(volume_urn, self.urn, lexicon.AFF4_IMAGE_CHUNK_SIZE,
                          rdfvalue.XSDInteger(self.chunk_size))

        self.resolver.Set(volume_urn, self.urn, lexicon.AFF4_IMAGE_CHUNKS_PER_SEGMENT,
                          rdfvalue.XSDInteger(self.chunks_per_segment))

        self.resolver.Set(volume_urn, self.urn, lexicon.AFF4_STREAM_SIZE,
                          rdfvalue.XSDInteger(self.Size()))


        for kb in self.keybags:
            self.resolver.Add(volume_urn, self.urn, lexicon.AFF4_KEYBAG,
                              rdfvalue.URN(kb.ID))
            kb.write(self.resolver, volume_urn)

registry.AFF4_TYPE_MAP[lexicon.AFF4_ENCRYPTEDSTREAM_TYPE] = AFF4EncryptedStream
registry.AFF4_TYPE_MAP[lexicon.AFF4_RANDOMSTREAM_TYPE] = RandomImageStream