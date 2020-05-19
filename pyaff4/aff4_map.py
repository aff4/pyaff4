# Copyright 2014 Google Inc. All rights reserved.
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

"""This module implements the standard AFF4 Image."""
from __future__ import print_function
from __future__ import unicode_literals
from builtins import str
from builtins import object
import collections
import intervaltree
import logging
import struct
import sys
import traceback

from pyaff4 import aff4
from pyaff4 import aff4_image
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import registry
from pyaff4 import utils

LOGGER = logging.getLogger("pyaff4")


class Range(collections.namedtuple(
        "Range", "map_offset length target_offset target_id")):
    """A class to manipulate a mapping range."""

    __slots__ = ()

    format_str = "<QQQI"

    @classmethod
    def FromSerialized(cls, string):
        return cls(*struct.unpack(cls.format_str, string))

    @classmethod
    def FromList(cls, list):
        return cls(*list)

    def Serialize(self):
        return struct.pack(self.format_str, *self)

    @property
    def map_end(self):
        return self.map_offset + self.length

    def target_offset_at_map_offset(self, offset):
        return self.target_offset + offset - self.map_offset

    def __repr__(self):
        return "<[%x:%x)->[%x:%x)@%s>" % (
            self.map_offset, self.length,
            self.target_offset, self.length,
            self.target_id)

    def Merge(self, other):
        """Merge two ranges together.

        Raises ValueError if the ranges can not be merged.
        """
        if (other.target_id != self.target_id or
                self.target_offset_at_map_offset(self.map_offset) !=
                other.target_offset_at_map_offset(self.map_offset)):
            raise ValueError("Ranges not mergeable")

        start = min(self.map_offset, other.map_offset)
        end = max(self.map_end, other.map_end)

        result = self._replace(
            map_offset=start,
            length=end-start,
            target_offset=self.target_offset_at_map_offset(start))

        return result

    def left_clip(self, offset):
        """Clip this range at the left side with offset."""
        if not self.map_offset <= offset <= self.map_end:
            raise ValueError("clip offset is not inside range")

        adjustment = offset - self.map_offset
        return self._replace(map_offset=self.map_offset + adjustment,
                             target_offset=self.target_offset + adjustment,
                             length=self.length - adjustment)

    def right_clip(self, offset):
        """Clip this range at the right side with offset."""
        if not self.map_offset <= offset <= self.map_end:
            raise ValueError("clip offset is not inside range")

        adjustment = self.map_end - offset
        return self._replace(length=self.length - adjustment)


class _MapStreamHelper(object):

    def __init__(self, resolver, source, destination):
        self.resolver = resolver
        self.range_offset = 0
        self.readptr = 0
        self.source = source
        self.destination = destination
        self.source_ranges = sorted(source.tree)
        if not self.source_ranges:
            raise RuntimeError("Source map is empty when calling WriteStream()")
        self.current_range_idx = 0

    def tell(self):
        return self.source.tell()

    def read(self, length):
        # This is the data stream of the map we are writing to (i.e. the new
        # image we are creating).
        target = self.destination.GetBackingStream()
        result = b""

        # Need more data - read more.
        while len(result) < length:
            # We are done! All source ranges read.
            if self.current_range_idx >= len(self.source_ranges):
                break

            current_range = self.source_ranges[self.current_range_idx].data

            # Add a range if we are at the beginning of a range.
            if self.range_offset == 0:
                self.destination.AddRange(
                    current_range.map_offset,
                    # This is the current offset in the data stream.
                    self.readptr,
                    current_range.length,
                    target)

            # Read as much data as possible from this range.
            to_read = min(
                # How much we need.
                length - len(result),
                # How much is available in this range.
                current_range.length - self.range_offset)

            # Range is exhausted - get the next range.
            if to_read == 0:
                self.current_range_idx += 1
                self.range_offset = 0
                continue

            # Read and copy the data.
            source_urn = self.source.targets[current_range.target_id]
            with self.resolver.AFF4FactoryOpen(source_urn) as source:
                source.SeekRead(current_range.target_offset + self.range_offset)

                data = source.Read(to_read)
                if not data:
                    break

                result += data
                self.range_offset += len(data)

                # Keep track of all the data we have released.
                self.readptr += len(data)

        return result

class AFF4Map(aff4.AFF4Stream):

    def __init__(self, *args, **kwargs):
        super(AFF4Map, self).__init__(*args, **kwargs)
        self.targets = []
        self.target_idx_map = {}
        self.tree = intervaltree.IntervalTree()
        self.last_target = None
        try:
            self.version = kwargs["version"]
        except:
            pass

    @staticmethod
    def NewAFF4Map(resolver, image_urn, volume_urn):
        with resolver.AFF4FactoryOpen(volume_urn) as volume:
            # Inform the volume that we have a new image stream contained within
            # it.
            volume.children.add(image_urn)

            resolver.Set(volume_urn, image_urn, lexicon.AFF4_TYPE, rdfvalue.URN(
                lexicon.AFF4_MAP_TYPE))

            resolver.Set(lexicon.transient_graph, image_urn, lexicon.AFF4_STORED,
                         rdfvalue.URN(volume_urn))

            res = resolver.AFF4FactoryOpen(image_urn)
            res.properties.writable = volume.properties.writable
            return res

    def deserializeMapPoint(self, data):
        return Range.FromSerialized(data)

    def LoadFromURN(self):
        map_urn = self.urn.Append("map")
        map_idx_urn = self.urn.Append("idx")

        # Parse the map out of the map stream. If the stream does not exist yet
        # we just start with an empty map.
        try:
            with self.resolver.AFF4FactoryOpen(map_idx_urn) as map_idx:
                self.targets = [rdfvalue.URN(utils.SmartUnicode(x))
                                for x in map_idx.Read(map_idx.Size()).splitlines()]

            with self.resolver.AFF4FactoryOpen(map_urn) as map_stream:
                read_length = struct.calcsize(Range.format_str)
                while 1:
                    data = map_stream.Read(read_length)
                    if not data:
                        break
                    range = self.deserializeMapPoint(data)
                    if range.length > 0:
                        self.tree.addi(range.map_offset, range.map_end, range)


        except IOError:
            traceback.print_exc()
            pass

    def Read(self, length):
        result = b""
        for interval in sorted(self.tree[self.readptr:self.readptr+length]):
            range = interval.data

            # The start of the range is ahead of us - we pad with zeros.
            if range.map_offset > self.readptr:
                padding = min(length, range.map_offset - self.readptr)
                result += b"\x00" * padding
                self.readptr += padding
                length -= padding

            if length == 0:
                break

            target = self.targets[range.target_id]
            length_to_read_in_target = min(length, range.map_end - self.readptr)

            bytes_read = 0
            try:
                with self.resolver.AFF4FactoryOpen(target, version=self.version) as target_stream:
                    target_stream.SeekRead(
                        range.target_offset_at_map_offset(self.readptr))

                    buffer = target_stream.Read(length_to_read_in_target)
                    if buffer == None:
                        bytes_read = 0
                    else:
                        bytes_read = len(buffer)
                        result += buffer

            except IOError:
                traceback.print_exc()
                LOGGER.debug("*** Stream %s not found. Substituting zeros. ***",
                             target_stream)
                result += b"\x00" * length_to_read_in_target
            finally:
                length -= bytes_read
                self.readptr += bytes_read

        return result

    def Size(self):
        return self.tree.end()

    def AddRange(self, map_offset, target_offset, length, target):
        """Add a new mapping range."""
        rdfvalue.AssertURN(target)
        self.last_target = target

        target_id = self.target_idx_map.get(target)
        if target_id is None:
            target_id = self.target_idx_map[target] = len(self.targets)
            self.targets.append(target)

        range = Range(map_offset, length, target_offset, target_id)

        # Try to merge with the left interval.
        left_interval = self.tree[range.map_offset-1]
        if left_interval:
            left_interval = left_interval.pop()

            try:
                range = range.Merge(left_interval.data)
            except ValueError:
                left_range = left_interval.data.right_clip(range.map_offset)
                # If the interval has not changed, then adding it to three will
                # not result in an additional interval (since the tree tries to
                # de-dup intervals). Therefore we will end up removing the
                # interval completely below. Therefore if clipping the interval
                # does not change it, we must discard the interval completely.
                if left_range == left_interval.data:
                    left_interval = None
                else:
                    self.tree.addi(
                        left_range.map_offset,
                        left_range.map_end,
                        left_range)

        # Try to merge with the right interval.
        right_interval = self.tree[range.map_end+1]
        if right_interval:
            right_interval = right_interval.pop()

            try:
                range = range.Merge(right_interval.data)
            except ValueError:
                right_range = right_interval.data.left_clip(range.map_end)
                if right_range == right_interval.data:
                    right_interval = None
                else:
                    self.tree.addi(
                        right_range.map_offset,
                        right_range.map_end,
                        right_range)

        # Remove the left and right intervals now. This must be done at this
        # point to allow for the case where left interval == right interval
        # (i.e. the same interval intersects both start and end).
        if left_interval:
            self.tree.remove(left_interval)

        if right_interval and right_interval != left_interval:
            self.tree.remove(right_interval)

        # Remove any intervals inside this range.
        self.tree.remove_envelop(range.map_offset, range.map_end)

        # Add the new interval.
        if range.length > 0:
            self.tree[range.map_offset:range.map_end] = range

        self.MarkDirty()

    def Flush(self):
        if self.IsDirty():
            # Get the volume we are stored on.
            volume_urn = self.resolver.GetUnique(lexicon.transient_graph, self.urn, lexicon.AFF4_STORED)
            with self.resolver.AFF4FactoryOpen(volume_urn) as volume:
                with volume.CreateMember(self.urn.Append("map")) as map_stream:
                    for interval in self.tree:
                        map_stream.Write(interval.data.Serialize())

                self.resolver.Close(map_stream)
                with volume.CreateMember(self.urn.Append("idx")) as idx_stream:
                    idx_stream.Write(b"\n".join(
                        [x.SerializeToString().encode("utf-8") for x in self.targets]))

                self.resolver.Close(idx_stream)
                #for target in self.targets:
                #    # for cross containterne references, opening the target wont work
                #    # so we enclose this in a try/catch
                #    try:
                #        # dont do this for hash references
                #        if target.SerializeToString().startswith("aff4:sha512"):
                #            continue
                #
                #        # Looks like the following is API misuse - we should let the Close happen automatically
                #        #with self.resolver.AFF4FactoryOpen(target) as stream:
                #        #    traceback.print_exc()
                #        #    pass
                #        #self.resolver.Close(stream)
                #    except:
                #        traceback.print_exc()
                #        pass


        return super(AFF4Map, self).Flush()

    def WriteStream(self, source, progress=None):
        data_stream_urn = self.GetBackingStream()
        with self.resolver.AFF4FactoryOpen(data_stream_urn) as data_stream:
            # If we write from another map we need to wrap the map in the
            # helper, otherwise we just copy the source into our data stream and
            # create a single range over the whole stream.
            if isinstance(source, AFF4Map):
                data_stream.WriteStream(
                    _MapStreamHelper(self.resolver, source, self), progress)
            else:
                data_stream.WriteStream(source, progress)

                # Add a single range to cover the bulk of the image.
                self.AddRange(0, data_stream.Size(), data_stream.Size(),
                              data_stream.urn)

    def GetBackingStream(self):
        """Returns the URN of the backing data stream of this map."""
        if self.targets:
            target = self.last_target
        else:
            target = self.urn.Append("data")

        try:
            with self.resolver.AFF4FactoryOpen(target) as stream:
                # Backing stream is fine - just use it.
                return stream.urn

        except IOError:
            # If the backing stream does not already exist, we make one.
            volume_urn = self.resolver.GetUnique(lexicon.transient_graph, self.urn, lexicon.AFF4_STORED)
            compression_urn = self.resolver.GetUnique(volume_urn,
                target, lexicon.AFF4_IMAGE_COMPRESSION)

            LOGGER.info("Stream will be compressed with %s", compression_urn)

            # If the stream should not be compressed, it is more efficient to
            # use a native volume member (e.g. ZipFileSegment or
            # FileBackedObjects) than the more complex bevy based images.
            if compression_urn in (lexicon.AFF4_IMAGE_COMPRESSION_STORED, 
                                    lexicon.AFF4_IMAGE_COMPRESSION_NONE):
                with self.resolver.AFF4FactoryOpen(volume_urn) as volume:
                    with volume.CreateMember(target) as member:
                        return member.urn

            with aff4_image.AFF4Image.NewAFF4Image(
                    self.resolver, target, volume_urn) as stream:
                return stream.urn

    def Write(self, data):
        self.MarkDirty()

        target = self.GetBackingStream()
        with self.resolver.AFF4FactoryOpen(target) as stream:
            self.AddRange(self.writeptr, stream.Size(), len(data), target)

            # Append the data on the end of the stream.
            stream.SeekWrite(stream.Size())
            stream.Write(data)

            self.writeptr += len(data)

        return len(data)

    def GetRanges(self):
        return sorted([x.data for x in self.tree])

    def Clear(self):
        self.targets = []
        self.target_idx_map.clear()
        self.tree.clear()

    def Close(self):
        pass


# Rekall/libAFF4 accidentally swapped the struct in Evimetry's update map
class ScudetteAFF4Map(AFF4Map):

    def deserializeMapPoint(self, data):
        # swap them back
        range = Range.FromSerialized(data)
        return Range(range[0], range[2], range[1], range[3])


class AFF4Map2(AFF4Map):
    def LoadFromURN(self):
        map_urn = self.urn.Append("map")
        map_idx_urn = self.urn.Append("idx")

        # Parse the map out of the map stream. If the stream does not exist yet
        # we just start with an empty map.
        try:
            with self.resolver.AFF4FactoryOpen(map_idx_urn, version=self.version) as map_idx:
                self.targets = [rdfvalue.URN(utils.SmartUnicode(x))
                                for x in map_idx.Read(map_idx.Size()).splitlines()]

            with self.resolver.AFF4FactoryOpen(map_urn, version=self.version) as map_stream:
                format_str = "<QQQI"
                bufsize = map_stream.Size()
                buf = map_stream.Read(bufsize)

                read_length = struct.calcsize(Range.format_str)

                lastUpperOffset = -1
                lastLowerOffset =  -1
                lastLength = -1
                lastTarget = -1

                offset = 0
                while offset < bufsize:
                    (upperOffset, length, lowerOffset, target) = struct.unpack_from(format_str, buf, offset)
                    offset += read_length

                    if lastUpperOffset == -1:
                        lastUpperOffset = upperOffset
                        lastLowerOffset = lowerOffset
                        lastLength = length
                        lastTarget = target
                        continue

                    if lastUpperOffset + lastLength == upperOffset and lastLowerOffset + lastLength == lowerOffset and lastTarget == target:
                        # these are adjoining
                        lastLength = lastLength + length
                        continue
                    else:
                        range = Range.FromList([lastUpperOffset, lastLength, lastLowerOffset, lastTarget])
                        if range.length > 0:
                            self.tree.addi(range.map_offset, range.map_end, range)
                        lastUpperOffset = upperOffset
                        lastLowerOffset = lowerOffset
                        lastLength = length
                        lastTarget = target

                range = Range.FromList([lastUpperOffset, lastLength, lastLowerOffset, lastTarget])
                if range.length > 0:
                    self.tree.addi(range.map_offset, range.map_end, range)

        except IOError:
            # we get IOErrors here on creation from scratch. This is safe and expected.
            pass

def isByteRangeARN(urn):
    if not urn.startswith("aff4://"):
        return False
    if not urn.endswith("]"):
        return False
    try:
        (target, rangepair) = urn.split("[")
        rangepair = rangepair[0:len(rangepair) - 1]
        (offset, length) = rangepair.split(":")

        offset = int(offset, 16)
        length = int(length, 16)
        return True
    except:
        return False

class ByteRangeARN(aff4.AFF4Stream):

    def __init__(self, version, resolver=None, urn=None):
        super(ByteRangeARN, self).__init__(
            resolver=resolver, urn=urn)
        (target, rangepair) = urn.SerializeToString().split("[")
        rangepair = rangepair[0:len(rangepair)-1]
        (offset, length) = rangepair.split(":")
        self.target = target
        self.offset = int(offset,16)
        self.length = int(length,16)
        self.version = version


    def Read(self, length):
        result = b""
        if self.readptr >= self.length:
            return None
        length_to_read_in_target = min(length, self.length)
        try:
            with self.resolver.AFF4FactoryOpen(self.target, version=self.version) as target_stream:
                #if target_stream.IsDirty():
                #    target_stream.FlushBuffers()
                target_stream.SeekRead(self.offset + self.readptr)
                buffer = target_stream.Read(length_to_read_in_target)
                assert len(buffer) == length_to_read_in_target
                result += buffer
        except IOError:
            LOGGER.debug("*** Stream %s not found. Substituting zeros. ***",
                         target_stream)
            result += b"\x00" * length_to_read_in_target
        finally:
            length -= length_to_read_in_target
            self.readptr += length_to_read_in_target
        return result

    def Write(self, data):
        raise NotImplementedError()

    def WriteStream(self, source):
        raise NotImplementedError()

    def Tell(self):
        return self.readptr

    def Size(self):
        return sys.maxsize

    def read(self, length=1024*1024):
        return self.Read(length)

    def seek(self, offset, whence=0):
        self.Seek(offset, whence=whence)

    def write(self, data):
        self.Write(data)

    def tell(self):
        return self.Tell()

    def flush(self):
        self.Flush()

    def Prepare(self):
        self.Seek(0)

registry.AFF4_TYPE_MAP[lexicon.AFF4_MAP_TYPE] = AFF4Map2
registry.AFF4_TYPE_MAP[lexicon.AFF4_LEGACY_MAP_TYPE] = AFF4Map
registry.AFF4_TYPE_MAP[lexicon.AFF4_SCUDETTE_MAP_TYPE] = ScudetteAFF4Map
