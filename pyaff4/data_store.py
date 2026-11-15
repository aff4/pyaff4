# Copyright 2014 Google Inc. All rights reserved.
# Copyright 2018 Schatz Forensic Pty. Ltd. All rights reserved.
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
import errno
import itertools
from os.path import expanduser
import collections
import logging
import rdflib
import re
import os
import tempfile
import traceback
import subprocess
import sys
import types
import binascii

from rdflib.term import URIRef, Literal, IdentifiedNode
from rdflib import XSD

from itertools import chain

import pyaff4.zip
from pyaff4 import aff4
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import registry
from pyaff4 import stream_factory
from pyaff4 import streams
from pyaff4 import aff4_map
from pyaff4 import aff4_image, encrypted_stream
from pyaff4 import escaping
from pyaff4 import turtle, hexdump
from pyaff4.rdfvalue import ARN
from pyaff4.zip import ZIP_DEFLATE, ZIP_STORED, ZipFile, ZipFileSegment
from pyaff4.lexicon import transient_graph, XSD_NAMESPACE, any
from pyaff4.aff4_map import isByteRangeARN

LOGGER = logging.getLogger("pyaff4")
HAS_HDT = False
try:
    from pyhdt2_cython.build import write_opidx_sidecar
    from pyhdt2_cython.hdt import Hdt
    from rdflib_hdt_ng import hdt_store, rdflib_bridge, union_store
    HAS_HDT = True
except ImportError:
    pass

HDT_SEGMENT = "information.hdt"
OPIDX_SEGMENT = "information.hdt.opidx"

# Coerce rdflib to use
#rdflib.term._toPythonMapping[URIRef(XSD_NAMESPACE + 'hexBinary')] = lambda s: binascii.unhexlify(s)

#HAS_HDT = False
def CHECK(condition, error):
    if not condition:
        raise RuntimeError(error)

def only_objects(it):
    for (s, p, o) in it:
        yield o

def ReadSegment(zip_file, name):
    with zip_file.OpenZipSegment(name) as fd:
        return streams.ReadAll(fd)

def LoadFromHdt(zip_file):
    """The read-only store for zip_file's information.hdt, with the information.hdt.opidx index
    sidecar when present, so the HDT engine can use it rather than building the
    object index itself."""
    opidx_bytes = None
    if zip_file.ContainsSegment(OPIDX_SEGMENT):
        opidx_bytes = ReadSegment(zip_file, OPIDX_SEGMENT)
    return hdt_store.HdtStore(ReadSegment(zip_file, HDT_SEGMENT), opidx_bytes=opidx_bytes)

class AFF4ObjectCacheEntry:
    def __init__(self, key, aff4_obj):
        self.next = self.prev = self
        self.key = key
        self.aff4_obj = aff4_obj
        self.use_count = 0

    def unlink(self):
        self.next.prev = self.prev
        self.prev.next = self.next
        self.next = self.prev = self

    def append(self, entry):
        CHECK(entry.next == entry.prev,
              "Appending an element already in the list")
        entry.next = self.next

        self.next.prev = entry

        entry.prev = self
        self.next = entry

    def __iter__(self):
        entry = self.next
        while entry != self:
            yield entry
            entry = entry.next


class AFF4ObjectCache:
    def __init__(self, max_items):
        self.max_items = max_items
        self.in_use = {}
        self.lru_map = {}
        self.lru_list = AFF4ObjectCacheEntry(None, None)
        self.volume_file_map = {}

    def _Trim(self, size=None):
        max_items = size or self.max_items
        while len(self.lru_map) > max_items:
            older_item = self.lru_list.prev
            #LOGGER.debug("Trimming %s from cache" % older_item.key)

            self.lru_map.pop(older_item.key)
            older_item.unlink()

            # Ensure we flush the trimmed objects.
            older_item.aff4_obj.Flush()

    def Put(self, aff4_obj, in_use_state=False):
        if type(aff4_obj) == aff4_map.ByteRangeARN:
            return
        key = aff4_obj.urn.toPython()

        #LOGGER.debug("Putting %s in cache" % key)
        CHECK(key not in self.in_use,
              u"Object %s Put in cache while already in use." % key)

        CHECK(key not in self.lru_map,
              u"Object %s Put in cache while already in cache." % key)

        entry = AFF4ObjectCacheEntry(key, aff4_obj)
        if in_use_state:
            entry.use_count = 1
            self.in_use[key] = entry
            return

        self.lru_list.append(entry)
        self.lru_map[key] = entry

        self._Trim()

    def Contains(self, urn):
        key = urn.toPython()
        entry = self.in_use.get(key)
        if entry is not None:
            return True

        entry = self.lru_map.get(key)
        if entry is not None:
            return True
        return False

    def Get(self, urn):
        key = urn.toPython()
        #LOGGER.debug("Getting %s from cache" % key)
        entry = self.in_use.get(key)
        if entry is not None:
            entry.use_count += 1
            return entry.aff4_obj

        # Hold onto the entry.
        entry = self.lru_map.pop(key, None)
        if entry is None:
            return None

        entry.use_count = 1

        # Remove it from the LRU list.
        entry.unlink()
        self.in_use[key] = entry

        return entry.aff4_obj

    def Return(self, aff4_obj):
        if type(aff4_obj) == aff4_image.AFF4SImage:
            print
        if type(aff4_obj) == aff4_map.ByteRangeARN:
            return
        key = aff4_obj.urn.toPython()
        #LOGGER.debug("Returning %s in cache" % key)
        entry = self.in_use.get(key)
        CHECK(entry is not None,
              u"Object %s Returned to cache, but it is not in use!" % key)
        CHECK(entry.use_count > 0,
              u"Returned object %s is not used." % key)

        entry.use_count -= 1
        if entry.use_count == 0:
            self.lru_list.append(entry)
            self.lru_map[key] = entry
            self.in_use.pop(key)

            self._Trim()

    def Remove(self, aff4_obj):
        if type(aff4_obj) == aff4_image.AFF4SImage:
            print
        key = aff4_obj.urn.toPython()
        #LOGGER.debug("Removing %s in cache" % key)
        entry = self.lru_map.pop(key, None)
        if entry is not None:
            entry.unlink()
            entry.aff4_obj.Flush()
            return

        # Is the item in use?
        entry = self.in_use.pop(key, None)
        if entry is not None:
            entry.unlink()
            entry.aff4_obj.Flush()
            return

        CHECK(False,
              "Object %s removed from cache, but was never there." % key)

    def Dump(self):
        # Now dump the objects in use.
        print("Objects in use:")
        for key, entry in list(self.in_use.items()):
            print(u"%s - %s" % (key, entry.use_count))

        print("Objects in cache:")
        for entry in self.lru_list:
            print(u"%s - %s" % (entry.key, entry.use_count))

    def Flush(self, partial=False):
        # It is an error to flush the object cache while there are still items
        # in use.
        if not partial and len(self.in_use):
            self.Dump()
            CHECK(len(self.in_use) == 0,
                  "ObjectCache flushed while some objects in use!")

        # First flush all objects without deleting them since some flushed
        # objects may still want to use other cached objects. It is also
        # possible that new objects are added during object deletion. Therefore
        # we keep doing it until all objects are clean.
        while 1:
            dirty_objects_found = False

            for it in self.lru_list:
                o = it.aff4_obj
                if o.IsDirty():
                    dirty_objects_found = True
                    LOGGER.debug("Flushing %s in cache" % it.key)
                    o.Flush()

            if not dirty_objects_found:
                break

        if partial:
            return

        # Now delete all entries.
        for it in list(self.lru_map.values()):
            aff4o = it.aff4_obj
            LOGGER.debug("Closing %s in cache" % it.key)
            aff4o.Close()
            it.unlink()


        # Clear the map.
        self.lru_map.clear()

class MemoryDataStore:
    aff4NS = None
    segmentCache = {}

    def __init__(self, lex=lexicon.standard, parent=None, store=None):
        self.lexicon = lex
        self.loadedVolumes = []
        self.containerMap = {}
        if store is not None:
            self.store = store
        else:
            self.store = rdflib.Graph()
        self.transient_store = rdflib.Graph()
        if parent is None:
            self.ObjectCache = AFF4ObjectCache(10)
        else:
            self.ObjectCache = parent.ObjectCache
        self.flush_callbacks = {}
        self.parent = parent

        if self.lexicon == lexicon.legacy:
            self.streamFactory = stream_factory.PreStdStreamFactory(
                self, self.lexicon)
        else:
            self.streamFactory = stream_factory.StdStreamFactory(
                self, self.lexicon)


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        try:
            self.Flush()
        except Exception:
            traceback.print_exc()
        if exc_type is not None:
            return False

    def Flush(self):
        # Flush and expunge the cache.
        if self.parent is None:
            self.ObjectCache.Flush()
        else:
            self.ObjectCache.Flush(partial=True)
        for cb in list(self.flush_callbacks.values()):
            cb()

    def DeleteSubject(self, subject):
        if (subject, None, None) in self.transient_store:
            self.transient_store.remove((subject, None, None))
        if (subject, None, None) in self.store:
            self.store.remove((subject, None, None))

    def CacheContains(self, arn):
        return self.ObjectCache.Contains(arn)

    def CacheGet(self, urn):
        result = self.ObjectCache.Get(urn)
        if result is None:
            return result
        else:
            return result
        #if result is None:
        #    result = aff4.NoneObject("Not present")

        #return result

    def CachePut(self, obj):
        self.ObjectCache.Put(obj, True)
        return obj

    def Return(self, obj):
        #LOGGER.debug("Returning %s" % obj.urn)
        if obj.closed:
            self.Close(obj)
        else:
            self.ObjectCache.Return(obj)

    def Close(self, obj):
        self.ObjectCache.Remove(obj)

    def _should_ignore(self, subject, predicate, object):

        if predicate == lexicon.AFF4_TYPE:
            if object == lexicon.AFF4_ZIP_SEGMENT_TYPE or object == lexicon.AFF4_ZIP_TYPE:
                return True
            else:
                return False

        if predicate == lexicon.AFF4_STORED:
            if not str(object).startswith(u"aff4://"):
                return True
            elif subject.startswith(object.SerializeToString()):
                return True

        return False

    def DumpToTurtle(self, zipcontainer, ):
        #infoARN = escaping.urn_from_member_name(u"information.turtle", zipcontainer.urn, zipcontainer.version)
        #mode = self.GetUnique(lexicon.transient_graph, zipcontainer.backing_store_urn, lexicon.AFF4_STREAM_WRITE_MODE)
        # The mode belongs to the file at the bottom of the backing chain. An encrypted
        # container's inner zip is backed by an AFF4EncryptedStream, which has no mode, inside
        # the outer zip, inside the file; walk down to the first backing object with a mode.
        mode = None
        backing = zipcontainer.parent
        while backing is not None:
            if hasattr(backing, 'mode'):
                mode = backing.mode
                break
            backing = getattr(backing, 'parent', None)
        if mode is not None and mode == "random":
            # random mode is used for appending to encrypted streams, where the stream size changes
            # snapshot mode creates the situation where we have multiple versions of the stream object
            # mashed together, and we cant tell the most recent
            turtle_append_mode="latest"
        else:
            # in append mode, we assume that each time we append, we are adding to the container, rather
            # than modifying any existing objects in the container. Because of this, we get to save multiple
            # independent copies of the turtle from each run, and join them together as text for efficiency
            turtle_append_mode="snapshot"

        if not zipcontainer.ContainsSegment(u"information.turtle"):
            with zipcontainer.CreateZipSegment(u"information.turtle") as turtle_segment:
                turtle_segment.compression_method = ZIP_STORED

                result = self._DumpToTurtle(zipcontainer.urn)
                turtle_segment.write(result.encode("utf-8"))
                turtle_segment.Flush()
            turtle_segment.Close()
        else:
            # append to an existing container
            self.invalidateCachedMetadata(zipcontainer)
            if turtle_append_mode == "latest":
                zipcontainer.RemoveSegment(u"information.turtle")
                with zipcontainer.CreateZipSegment(u"information.turtle") as turtle_segment:
                    turtle_segment.compression_method = ZIP_STORED

                    result = self._DumpToTurtle(zipcontainer.urn)
                    turtle_segment.write(result.encode("utf-8"))
                    turtle_segment.Flush()
                turtle_segment.Close()
                return

            #explodedTurtleDirectivesARN = escaping.urn_from_member_name(u"information.turtle/directives", zipcontainer.urn, zipcontainer.version)
            if not zipcontainer.ContainsSegment(u"information.turtle/directives"):
                # this is the first append operation. Create the chunked turtle structures
                with zipcontainer.OpenZipSegment(u"information.turtle") as turtle_segment:
                    currentTurtle= streams.ReadAll(turtle_segment).decode("utf-8")
                    #hexdump.hexdump(currentTurtleBytes)
                    (directives_txt, triples_txt) = turtle.toDirectivesAndTripes(currentTurtle)
                    with zipcontainer.CreateZipSegment(u"information.turtle/directives") as directives_segment:
                        directives_segment.compression_method = ZIP_DEFLATE
                        directives_segment.write(directives_txt.encode("utf-8"))
                        directives_segment.Flush()
                    directives_segment.Close()
                    with zipcontainer.CreateZipSegment(u"information.turtle/%08d" % 0) as turtle_chunk_segment:
                        turtle_chunk_segment.compression_method = ZIP_DEFLATE
                        turtle_chunk_segment.write(triples_txt.encode("utf-8"))
                        turtle_chunk_segment.Flush()
                    self.Close(turtle_chunk_segment)
                turtle_segment.Close()

                (current_directives_txt, current_triples_txt) = turtle.toDirectivesAndTripes(self._DumpToTurtle(zipcontainer.urn))
                directives_difference = turtle.difference(directives_txt, current_directives_txt)
                if not len(directives_difference) == 0:
                    directives_txt = directives_txt + u"\r\n" + directives_difference
                    zipcontainer.RemoveSegment("information.turtle/directives")
                    with zipcontainer.CreateZipSegment(u"information.turtle/directives") as directives_segment:
                        directives_segment.compression_method = ZIP_DEFLATE
                        directives_segment.write(directives_txt.encode("utf-8"))
                        directives_segment.Flush()
                    directives_segment.Close()

                #current_turtle_chunk_arn = rdfvalue.URN(u"%s/information.turtle/%08d" % (zipcontainer.urn, 1))
                current_turtle_chunk_name = u"information.turtle/%08d" % 1
                with zipcontainer.CreateZipSegment(current_turtle_chunk_name) as turtle_segment:
                    turtle_segment.compression_method = ZIP_DEFLATE
                    turtle_segment.write(current_triples_txt.encode("utf-8"))
                    turtle_segment.Flush()
                self.Close(turtle_segment)

                zipcontainer.RemoveSegment(u"information.turtle")
                with zipcontainer.CreateZipSegment(u"information.turtle") as turtle_segment:
                    turtle_segment.compression_method = ZIP_STORED
                    padded_directives_txt = directives_txt + u"\r\n\r\n"
                    turtle_segment.write(padded_directives_txt.encode("utf-8"))

                    # Chunks 0 and 1 were written in this session, so use their text rather than
                    # reading them back: an encrypted backing stream may not return unflushed data.
                    for turtle_chunk_txt in (triples_txt, current_triples_txt):
                        turtle_segment.write((turtle_chunk_txt + "\r\n").encode("utf-8"))
                    turtle_segment.Flush()
                turtle_segment.Close()
            else:
                # more than one append as already occurred
                turtleContainerIndex = 0
                while True:
                    #turtleARN = escaping.urn_from_member_name(u"information.turtle/%08d" % turtleContainerIndex,
                    #                                                            zipcontainer.urn, zipcontainer.version)
                    turtle_name = u"information.turtle/%08d" % turtleContainerIndex
                    if not zipcontainer.ContainsSegment(turtle_name):
                        break
                    turtleContainerIndex = turtleContainerIndex + 1

                with zipcontainer.OpenZipSegment(u"information.turtle/directives") as directives_segment:
                    directives_txt = streams.ReadAll(directives_segment).decode("utf-8")

                (current_directives_txt, current_triples_txt) = turtle.toDirectivesAndTripes(self._DumpToTurtle(zipcontainer.urn))
                directives_difference = turtle.difference(directives_txt, current_directives_txt)

                if len(directives_difference) > 0:
                    directives_txt = directives_txt + u"\r\n" + u"\r\n".join(directives_difference)
                    zipcontainer.RemoveSegment("information.turtle/directives")
                    with zipcontainer.CreateZipSegment(u"information.turtle/directives") as directives_segment:
                        directives_segment.compression_method = ZIP_DEFLATE
                        directives_segment.write(directives_txt.encode("utf-8"))
                        directives_segment.Flush()
                    directives_segment.Close()

                new_chunk_index = turtleContainerIndex
                new_chunk_name = "information.turtle/%08d" % new_chunk_index
                with zipcontainer.CreateZipSegment(new_chunk_name) as turtle_segment:
                    turtle_segment.compression_method = ZIP_DEFLATE
                    turtle_segment.write(current_triples_txt.encode("utf-8"))
                    turtle_segment.Flush()
                turtle_segment.Close()

                zipcontainer.RemoveSegment("information.turtle")
                with zipcontainer.CreateZipSegment(u"information.turtle") as turtle_segment:
                    turtle_segment.compression_method = ZIP_DEFLATE
                    padded_directives_txt = directives_txt + u"\r\n\r\n"
                    turtle_segment.write(padded_directives_txt.encode("utf-8"))

                    # Earlier chunks come from earlier sessions and are read back; the newest was
                    # written in this session, so its text is used directly (see above).
                    for index in range(new_chunk_index):
                        chunk_name = "information.turtle/%08d" % index
                        with zipcontainer.OpenZipSegment(chunk_name) as turtle_chunk_segment:
                            turtle_chunk_txt = streams.ReadAll(turtle_chunk_segment).decode("utf-8")
                        turtle_segment.write((turtle_chunk_txt + "\r\n").encode("utf-8"))
                    turtle_segment.write((current_triples_txt + "\r\n").encode("utf-8"))
                    turtle_segment.Flush()
                turtle_segment.Close()

    def DumpToHdt(self, zipcontainer):
        """Write the volume's whole graph as information.hdt, with its object index as
        information.hdt.opidx, replacing any earlier ones: readers prefer the HDT to
        information.turtle, so it must hold everything the turtle does.

        Encrypted containers get no HDT: their metadata stays in information.turtle only."""
        if not HAS_HDT or self._isEncryptedContainer(zipcontainer):
            return
        hdt_bytes = rdflib_bridge.graph_to_hdt_bytes(self.store, base_iri=str(zipcontainer.urn))
        opidx_bytes = write_opidx_sidecar(*Hdt(hdt_bytes).op_index_arrays())
        for name, data in ((HDT_SEGMENT, hdt_bytes), (OPIDX_SEGMENT, opidx_bytes)):
            if zipcontainer.ContainsSegment(name):
                zipcontainer.RemoveSegment(name)
            with zipcontainer.CreateZipSegment(name) as segment:
                segment.compression_method = ZIP_STORED
                segment.write(data)
                segment.Flush()
            segment.Close()

    def _isEncryptedContainer(self, zipcontainer):
        """Whether zipcontainer is the outer volume of an encrypted container (it holds an
        encrypted stream) or the inner one (it is stored in an encrypted stream)."""
        if isinstance(zipcontainer.parent, encrypted_stream.AFF4EncryptedStream):
            return True
        return (None, lexicon.AFF4_TYPE, lexicon.AFF4_ENCRYPTEDSTREAM_TYPE) in self.store

    def _DumpToTurtle(self, volumeurn, verbose=False):
        g = self.store
        g.bind("aff4", rdflib.Namespace(self.lexicon.base))

        # looks like rdflib has some problems with re-constituting subjects using @base
        # comment out for now
        #volumeNamespace = rdflib.Namespace(volumeurn.value + "/")
        #volumeBase = volumeurn.value + "/"


        result = g.serialize(format='turtle')
        return result

    def addExistingContainer(self, member_container):
        arn = member_container.urn
        self.containerMap[arn] = member_container
        self.store = self.createStoreFromZip(member_container.zip)

    def addNewContainer(self, member_container):
        arn = member_container.urn
        self.containerMap[arn] = member_container

    def loadMetadata(self, member_container):
        # Load the turtle metadata.
        #if zip.urn not in self.loadedVolumes:
        with member_container.zip.OpenZipSegment("information.turtle") as fd:
            self.LoadFromTurtle(fd, member_container.urn)
            self.loadedVolumes.append(member_container.urn)

    def LoadFromTurtle(self, stream, volume_arn):
        data = streams.ReadAll(stream).decode("utf-8")
        self.store.parse(data=data, format="turtle")

        # look for the AFF4 namespace defined in the turtle
        for (_, b) in self.store.namespace_manager.namespaces():
            if (str(b) == lexicon.AFF4_NAMESPACE or
                str(b) == lexicon.AFF4_LEGACY_NAMESPACE):
                self.aff4NS = b
        return self.store

    def createStoreFromZip(self, zip_file):
        # A container opened for writing loads its turtle, which is always written alongside
        # the HDT, so that its statements can be changed.
        if not zip_file.properties.writable and zip_file.ContainsSegment(HDT_SEGMENT):
            return self.addHdt(LoadFromHdt(zip_file))
        elif zip_file.ContainsSegment("information.turtle"):
            with zip_file.OpenZipSegment("information.turtle") as fd:
                return self.LoadFromTurtle(fd, zip_file.urn)

    def addHdt(self, hdt):
        """Add a read-only HDT store's statements to the metadata, which from then on is a
        union of the HDT stores loaded so far and a mutable graph holding everything else."""
        union = self.store.store
        if not isinstance(union, union_store.HdtUnionStore):
            union = union_store.HdtUnionStore(self.store)
            self.store = rdflib.Graph(union)
        union.add_hdt(hdt)
        return self.store

    def AFF4FactoryOpen(self, urn, version=None, prototype=None):
        # Is the object cached?
        cached_obj = self.ObjectCache.Get(urn)
        if cached_obj:
            cached_obj.Prepare()
            #LOGGER.debug("AFF4FactoryOpen (Cached): %s" % urn)
            return cached_obj

        if self.streamFactory.isSymbolicStream(urn):
            obj = self.streamFactory.createSymbolic(urn)
        elif urn.startswith("aff4:sha512"):
            # Don't use the cache for these as they are low cost
            # and they will push aside heavier weight things
            #bytestream_reference_id = self.Get(urn, urn, rdfvalue.URN(lexicon.standard.dataStream))
            #cached_obj = self.ObjectCache.Get(bytestream_reference_id)
            #if cached_obj:
            #    cached_obj.Prepare()
            #    return cached_obj
            bytestream_reference_id = self.GetUnique(lexicon.any, urn, lexicon.standard.dataStream)
            return aff4_map.ByteRangeARN(version, resolver=self, urn=bytestream_reference_id)
        elif isByteRangeARN(urn):
            return aff4_map.ByteRangeARN(version, resolver=self, urn=urn)
        else:
            uri_types = list(self.Get(lexicon.any, urn, lexicon.AFF4_TYPE))
            handler = None
            parent = None
            obj = None
            for typ in uri_types:
                handler = registry.AFF4_TYPE_MAP.get(typ)
                if handler is not None:
                    break

            if handler is None:
                # Try to instantiate the handler based on the URN scheme alone.
                (components, original_filename) = rdfvalue.Parse(urn.toPython())
                handler = registry.AFF4_TYPE_MAP.get(components.scheme)

            # we may find an aff4:Image, with no mixin supertypes. If it is zero length, dont throw, return a
            # zero sized stream
            if handler is None and len(uri_types) > 0:
                stream_size = next(self.Get(lexicon.any, urn, lexicon.AFF4_STREAM_SIZE), None)
                if stream_size is not None:
                    stream_size = stream_size.toPython()
                    if stream_size == 0:
                        handler = aff4.EmptyStream

            # check known containers for segments corresponding to this member
            # fastpath for volume scoped ARN's
            if handler is None:
                for v in self.containerMap.keys():
                    if urn.startswith(v):
                        p = self.containerMap[v]
                        segment_name = escaping.member_name_for_urn(urn, p.version, v)
                        zip_info = p.zip.members.get(segment_name, None)
                        if zip_info is not None:
                            parent = p.zip
                            obj = ZipFileSegment(self, urn, parent, version=version)
                            obj.filename = segment_name
                            break

            # check known containers for segments corresponding to this member
            # slowpath for universally scoped ARN's
            if parent is None:
                for v in self.containerMap.keys():
                    p = self.containerMap[v]
                    segment_name = escaping.member_name_for_urn(urn, p.version, v)
                    zip_info = p.zip.members.get(segment_name, None)
                    if zip_info is not None:
                        parent = p.zip
                        obj = ZipFileSegment(self, urn, parent, version=version)
                        obj.filename = segment_name
                        break

            # Only fall back to the parent resolver if we couldn't resolve the
            # URN locally. Doing this AFTER the containerMap walk lets nested
            # containers (e.g. an inner LogicalImageContainer inside an
            # encrypted volume, with a child resolver pointing at the outer
            # one) find their own segments before the parent is consulted.
            if handler is None and obj is None and self.parent is not None:
                try:
                    o = self.parent.AFF4FactoryOpen(urn)
                    if o is not None:
                        return o
                except IOError:
                    pass

            # find the parent of this member
            # fastpath for volume scoped ARN's
            if parent is None:
                for v in self.containerMap.keys():
                    if urn.startswith(v):
                        parent = self.containerMap[v]
                        break

            # find the parent of this member
            # slowpath for universally scoped ARN's
            if parent is None:
                for v in self.containerMap.keys():
                    p = self.containerMap[v]
                    segment_name = escaping.member_name_for_urn(urn, p.version, v)
                    zip_info = p.zip.members.get(segment_name, None)
                    if zip_info is not None:
                        parent = p
                        break

            if parent is None:
                for v in self.containerMap.keys():
                    p = self.containerMap[v]
                    parent = p
                    break

            if handler is None and obj is None:
                raise IOError("Unable to create object %s" % urn)

            if obj is None:
                obj = handler(self, urn, parent, version=version, prototype=prototype)
            obj.LoadFromURN()

        # Cache the object for next time.
        self.ObjectCache.Put(obj, True)

        #LOGGER.debug("AFF4FactoryOpen (new instance): %s" % urn)
        obj.Prepare()
        return obj

    def Dump(self, verbose=False):
        print(self.DumpToTurtle(verbose=verbose))
        self.ObjectCache.Dump()

    def isImageStream(self, subject):
        for t in self.store.objects(subject, lexicon.AFF4_TYPE):
            if t == lexicon.AFF4_LEGACY_IMAGE_TYPE or t == lexicon.AFF4_IMAGE_TYPE:
                return True
        return False

    # FIXME: This is a big API breaking change - we simply can not
    # change the type we are returning from Get() depending on random
    # factors. We need to make the store _always_ hold a list for all
    # members.
    def Add(self, graph, subject, attribute, value):
        CHECK(isinstance(graph, rdflib.term.URIRef), "Value must be an URIRef")
        CHECK(isinstance(subject, rdflib.term.URIRef), "Value must be an URIRef")
        CHECK(isinstance(attribute, rdflib.term.URIRef), "Value must be an URIRef")
        CHECK((isinstance(value, IdentifiedNode) or isinstance(value, Literal)), "Value must be an IdentifiedNode or Literal")

        # if subject.startswith(u"aff4:sha512:"):
        #     raise Exception("Not sure what to do here")

        if graph == transient_graph:
            store = self.transient_store
        else:
            store = self.store

        store.add((subject, attribute, value))

    # only used for setting a single value
    def Set(self, graph, subject, attribute, value):
        CHECK(graph is None or isinstance(graph, rdflib.term.URIRef), "Value must be an URIRef")
        CHECK(isinstance(subject, rdflib.term.URIRef), "Value must be an URIRef")
        CHECK(isinstance(attribute, rdflib.term.URIRef), "Value must be an URIRef")
        CHECK((isinstance(value, IdentifiedNode) or isinstance(value, Literal)), "Value must be an IdentifiedNode or Literal")

        if graph == transient_graph:
            store = self.transient_store
        else:
            store = self.store

        store.remove((subject, attribute, None))
        store.add((subject, attribute, value))

    # return a list of results
    def Get(self, graph, subject, attribute):
        CHECK(graph is None or isinstance(graph, rdflib.term.URIRef), "Value must be an URIRef")
        CHECK(isinstance(subject, rdflib.term.URIRef), "Value must be an URIRef")
        CHECK(isinstance(attribute, rdflib.term.URIRef), "Value must be an URIRef")

        if graph == lexicon.any or graph is None:
            resa = self.transient_store.objects(subject, attribute)
            resb = self.store.objects(subject, attribute)
            return chain(resa, resb)
        elif graph == transient_graph:
            res = self.transient_store.objects(subject, attribute)
            return res
        else:
            res = self.store.objects(subject, attribute)
            return res

    # return a single result or None
    def GetUnique(self, graph, subject, attribute):
        res = self.Get(graph, subject, attribute)
        if isinstance (res, list):
            if len(res) == 1:
                return res[0]
            return None
        elif isinstance(res, types.GeneratorType) or isinstance(res, itertools.chain):
            return next(res, None)
        else:
            return res

    def QuerySubject(self, graph, subject_regex=None):
        if isinstance(subject_regex, str):
            subject_regex = subject_regex.encode("utf-8")
        subject_regex = re.compile(subject_regex)

        if graph == lexicon.any or graph is None:
            storeitems = chain(self.store.items(), self.transient_store.items())
        elif graph == transient_graph:
            storeitems = self.transient_store.items()
        else:
            storeitems = self.store.items()

        for subject in storeitems:
            if subject_regex is not None and subject_regex.match(subject):
                yield rdfvalue.URN().UnSerializeFromString(subject)

    def QueryPredicate(self, graph, predicate):
        """Yields all subjects which have this predicate."""
        if isinstance(predicate, str):
            predicate = predicate.encode("utf-8")

        if graph == lexicon.any or graph is None:
            storeitems = chain(self.store.items(), self.transient_store.items())
        elif graph == transient_graph:
            storeitems = self.transient_store.items()
        else:
            storeitems = self.store.items()

        for subject, data in storeitems:
            for pred, values in data.items():
                if pred == predicate:
                    if type(values) != type([]):
                        values = [values]
                    for value in values:
                        yield (rdfvalue.URN().UnSerializeFromString(subject),
                               rdfvalue.URN().UnSerializeFromString(predicate),
                               value)


    def QueryPredicateObject(self, graph, predicate, object):
        if graph == lexicon.any or graph is None:
            subjects = chain(self.store.subjects(predicate, object), self.transient_store.subjects(predicate, object))
        elif graph == transient_graph:
            subjects = self.transient_store.subjects(predicate, object)
        else:
            subjects = self.store.subjects(predicate, object)
        return subjects

    def QuerySubjectPredicate(self, graph, subject, predicate):
        if graph == lexicon.any or graph is None:
            objects = chain(self.store.objects(subject, predicate), self.transient_store.objects(subject, predicate))
        elif graph == transient_graph:
            objects = self.transient_store.objects(subject, predicate)
        else:
            objects = self.store.objects(subject, predicate)
        return objects


    def SelectSubjectsByPrefix(self, graph, prefix):
        if graph == lexicon.any or graph is None:
            subjects = chain(self.store.subjects(unique=True),
                             self.transient_store.subjects(unique=True))
        elif graph == transient_graph:
            subjects = self.transient_store.subjects(unique=True)
        else:
            subjects = self.store.subjects(unique=True)

        for subject in subjects:
            if subject.startswith(prefix):
                if type(subject) == URIRef:
                    yield ARN(subject.toPython())
                else:
                    yield subject

    def QueryPredicatesBySubject(self, graph, subject):
        if isinstance(subject, bytes):
            subject = subject.decode("utf-8")
        else:
            subject = str(subject)

        if graph == transient_graph:
            store = self.transient_store
        else:
            store = self.store

        for pred, value in list(store.get(subject, {}).items()):
            yield (rdfvalue.URN().UnSerializeFromString(pred), value)

    def invalidateCachedMetadata(self, zip):
        pass

# With large information.turtle files, the in-memory database performs
# horribly. This is a faster way. http://www.rdfhdt.org
class HDTAssistedDataStore(MemoryDataStore):
    def __init__(self, lex=lexicon.standard):
        super().__init__(lex=lex)
        self.hdt = None

    # not yet implemented
    # def QueryPredicate(self, graph, predicate):
    #     if graph == transient_graph:
    #         yield super().QueryPredicate(transient_graph, predicate)
    #
    #     yield super().QueryPredicate(graph, predicate)

    # def QueryPredicateObject(self, graph, predicate, object):
    #     (triples, cardinality) = self.hdt.search_triples("", predicate, object)
    #
    #     for (s,p,o) in triples:
    #         yield rdfvalue.URN(s)
    #
    #     for subject in super().QueryPredicateObject(graph, predicate, object):
    #         yield subject

    def Get(self, graph, subject, attribute):
        if self.hdt is None:
            return super().Get(graph, subject, attribute)
        else:
            # we use a set here as we some implementations might pass up an object from
            # the persisted graph and the transient graph. The set lets us remove duplicates
            # res = set(self.QuerySubjectPredicate(graph, subject, attribute))
            # if len(res) == 1:
            return super().Get(graph, subject, attribute)

    # def SelectSubjectsByPrefix(self, graph, prefix):
    #     if graph == transient_graph:
    #         yield super().SelectSubjectsByPrefix(transient_graph, prefix)
    #
    #     yield super().SelectSubjectsByPrefix(graph, prefix)
    #
    # def QueryPredicatesBySubject(self, graph, subject):
    #     if graph == transient_graph:
    #         yield super().QueryPredicatesBySubject(transient_graph, subject)
    #
    #     yield super().QueryPredicatesBySubject(graph, subject)

