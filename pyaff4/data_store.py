from __future__ import print_function
from __future__ import unicode_literals
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

from builtins import str
from builtins import object
import collections
import logging
import rdflib
import re
import six

from pyaff4 import aff4
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import registry
from pyaff4 import stream_factory
from pyaff4 import utils
from pyaff4 import streams
from pyaff4 import aff4_file

LOGGER = logging.getLogger("pyaff4")


def CHECK(condition, error):
    if not condition:
        raise RuntimeError(error)

class AFF4ObjectCacheEntry(object):
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


class AFF4ObjectCache(object):
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
            LOGGER.debug("Trimming %s from cache" % older_item.key)

            self.lru_map.pop(older_item.key)
            older_item.unlink()

            # Ensure we flush the trimmed objects.
            older_item.aff4_obj.Flush()

    def Put(self, aff4_obj, in_use_state=False):
        key = aff4_obj.urn.SerializeToString()
        CHECK(key not in self.in_use,
              u"Object %s Put in cache while already in use." % utils.SmartUnicode(key))

        CHECK(key not in self.lru_map,
              u"Object %s Put in cache while already in cache." % utils.SmartUnicode(key))

        entry = AFF4ObjectCacheEntry(key, aff4_obj)
        if in_use_state:
            entry.use_count = 1
            self.in_use[key] = entry
            return

        self.lru_list.append(entry)
        self.lru_map[key] = entry

        self._Trim()

    def Get(self, urn):
        key = rdfvalue.URN(urn).SerializeToString()
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
        key = aff4_obj.urn.SerializeToString()
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
        key = aff4_obj.urn.SerializeToString()
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
            print(u"%s - %s" % (utils.SmartUnicode(key), entry.use_count))

        print("Objects in cache:")
        for entry in self.lru_list:
            print(u"%s - %s" % (utils.SmartUnicode(entry.key), entry.use_count))

    def Flush(self):
        # It is an error to flush the object cache while there are still items
        # in use.
        if len(self.in_use):
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
                if it.aff4_obj.IsDirty():
                    dirty_objects_found = True
                    it.aff4_obj.Flush()

            if not dirty_objects_found:
                break

        # Now delete all entries.
        for it in list(self.lru_map.values()):
            aff4o = it.aff4_obj
            aff4o.Close()
            it.unlink()


        # Clear the map.
        self.lru_map.clear()


class MemoryDataStore(object):
    aff4NS = None

    def __init__(self, lex=lexicon.standard):
        self.lexicon = lex
        self.store = collections.OrderedDict()
        self.ObjectCache = AFF4ObjectCache(10)
        self.flush_callbacks = {}

        if self.lexicon == lexicon.legacy:
            self.streamFactory = stream_factory.PreStdStreamFactory(
                self, self.lexicon)
        else:
            self.streamFactory = stream_factory.StdStreamFactory(
                self, self.lexicon)


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.Flush()

    def Flush(self):
        # Flush and expunge the cache.
        self.ObjectCache.Flush()
        for cb in list(self.flush_callbacks.values()):
            cb()

    def DeleteSubject(self, subject):
        self.store.pop(rdfvalue.URN(subject), None)

    # FIXME: This is a big API breaking change - we simply can not
    # change the type we are returning from Get() depending on random
    # factors. We need to make the store _always_ hold a list for all
    # members.
    def Add(self, subject, attribute, value):
        subject = rdfvalue.URN(subject).SerializeToString()
        attribute = rdfvalue.URN(attribute).SerializeToString()
        CHECK(isinstance(value, rdfvalue.RDFValue), "Value must be an RDFValue")

        if attribute not in self.store.setdefault(
                subject, collections.OrderedDict()):
            self.store.get(subject)[attribute] = value
        else:
            oldvalue = self.store.get(subject)[attribute]
            t = type(oldvalue)
            if  t != type([]):
                if value != oldvalue:
                    self.store.get(subject)[attribute] = [oldvalue, value]
            else:
                if value not in oldvalue:
                    oldvalue.append(value)

    def Set(self, subject, attribute, value):
        subject = rdfvalue.URN(subject).SerializeToString()
        attribute = rdfvalue.URN(attribute).SerializeToString()
        CHECK(isinstance(value, rdfvalue.RDFValue), "Value must be an RDFValue")

        self.store.setdefault(subject, {})[attribute] = value

    def Get(self, subject, attribute):
        subject = rdfvalue.URN(subject).SerializeToString()
        attribute = rdfvalue.URN(attribute).SerializeToString()
        vals = self.store.get(subject, {})
        return vals.get(attribute)

    def CacheGet(self, urn):
        result = self.ObjectCache.Get(urn)
        if result is None:
            result = aff4.NoneObject("Not present")

        return result

    def CachePut(self, obj):
        self.ObjectCache.Put(obj, True)
        return obj

    def Return(self, obj):
        #LOGGER.debug("Returning %s" % obj.urn)
        self.ObjectCache.Return(obj)

    def Close(self, obj):
        self.ObjectCache.Remove(obj)

    def _should_ignore(self, subject, predicate, object):

        if predicate == lexicon.AFF4_TYPE:
            if object == lexicon.AFF4_ZIP_SEGMENT_TYPE or object == object == lexicon.AFF4_ZIP_TYPE:
                return True
            else:
                return False

        if predicate == lexicon.AFF4_STORED:
            if not str(object).startswith(u"aff4://"):
                return True
            elif subject.startswith(object.SerializeToString()):
                return True

        return False


    def DumpToTurtle(self, volumeurn, stream=None, verbose=False):
        g = rdflib.Graph()
        g.bind("aff4", rdflib.Namespace(self.lexicon.base))

        # looks like rdflib has some problems with re-constituting subjects using @base
        # comment out for now
        #volumeNamespace = rdflib.Namespace(volumeurn.value + "/")
        #volumeBase = volumeurn.value + "/"

        for urn, items in self.store.items():
            urn = utils.SmartUnicode(urn)
            type = items.get(utils.SmartUnicode(lexicon.AFF4_TYPE))
            if type is None:
                continue

            for attr, value in list(items.items()):
                attr = utils.SmartUnicode(attr)
                # We suppress certain facts which can be deduced from the file
                # format itself. This ensures that we do not have conflicting
                # data in the data store. The data in the data store is a
                # combination of explicit facts and implied facts.
                if not verbose:
                    if attr.startswith(lexicon.AFF4_VOLATILE_NAMESPACE):
                        continue

                if not isinstance(value, list):
                    value = [value]

                for item in value:
                    if self._should_ignore(urn, attr, item):
                        continue
                    g.add((rdflib.URIRef(urn), rdflib.URIRef(attr), item.GetRaptorTerm()))

        #result = g.serialize(format='turtle', base=volumeNamespace)
        result = g.serialize(format='turtle')
        result = utils.SmartUnicode(result)
        #basestart = "@base <%s> .\r\n" % (volumeBase)
        #result = basestart + result
        if stream:
            stream.write(utils.SmartStr(result))

        return result


    def LoadFromTurtle(self, stream):
        data = streams.ReadAll(stream)
        g = rdflib.Graph()
        g.parse(data=data, format="turtle")

        for urn, attr, value in g:
            urn = utils.SmartUnicode(urn)
            attr = utils.SmartUnicode(attr)
            serialized_value = value

            if isinstance(value, rdflib.URIRef):
                value = rdfvalue.URN(utils.SmartUnicode(serialized_value))
            elif value.datatype in registry.RDF_TYPE_MAP:
                dt = value.datatype
                value = registry.RDF_TYPE_MAP[value.datatype](
                    serialized_value)

            else:
                # Default to a string literal.
                value = rdfvalue.XSDString(value)

            self.Add(urn, attr, value)

        # look for the AFF4 namespace defined in the turtle
        for (_, b) in g.namespace_manager.namespaces():
            if (str(b) == lexicon.AFF4_NAMESPACE or
                str(b) == lexicon.AFF4_LEGACY_NAMESPACE):
                self.aff4NS = b

    def AFF4FactoryOpen(self, urn, version=None):
        urn = rdfvalue.URN(urn)

        # Is the object cached?
        cached_obj = self.ObjectCache.Get(urn)
        if cached_obj:
            cached_obj.Prepare()
            #LOGGER.debug("AFF4FactoryOpen (Cached): %s" % urn)
            return cached_obj

        if self.streamFactory.isSymbolicStream(urn):
            obj = self.streamFactory.createSymbolic(urn)
        else:
            uri_types = self.Get(urn, lexicon.AFF4_TYPE)

            handler = None

            # TODO: this could be cleaner. RDF properties have multiple values
            if type(uri_types) == type([]):
                for typ in uri_types:
                    handler = registry.AFF4_TYPE_MAP.get(typ)
                    if handler is not None:
                        break
            else:
                handler = registry.AFF4_TYPE_MAP.get(uri_types)

            if handler is None:
                # Try to instantiate the handler based on the URN scheme alone.
                components = urn.Parse()
                handler = registry.AFF4_TYPE_MAP.get(components.scheme)

            if handler is None:
                raise IOError("Unable to create object %s" % urn)

            obj = handler(resolver=self, urn=urn, version=version)
            obj.LoadFromURN()

        # Cache the object for next time.
        self.ObjectCache.Put(obj, True)

        #LOGGER.debug("AFF4FactoryOpen (new instance): %s" % urn)
        obj.Prepare()
        return obj

    def Dump(self, verbose=False):
        print(utils.SmartUnicode(self.DumpToTurtle(verbose=verbose)))
        self.ObjectCache.Dump()

    def isImageStream(self, subject):
        try:
            po = self.store[subject]
            if po == None:
                return False
            else:
                o = po[lexicon.AFF4_TYPE]
                if o == None:
                    return False
                else:
                    if type(o) == type([]):
                        for ent in o:
                            if ent.value == lexicon.AFF4_LEGACY_IMAGE_TYPE or ent.value == lexicon.AFF4_IMAGE_TYPE :
                                return True
                        return False
                    else:
                        if o.value == lexicon.AFF4_LEGACY_IMAGE_TYPE or o.value == lexicon.AFF4_IMAGE_TYPE :
                            return True
                        else:
                            return False
        except:
            return False

    def QuerySubject(self, subject_regex=None):
        subject_regex = re.compile(utils.SmartStr(subject_regex))
        for subject in self.store:
            if subject_regex is not None and subject_regex.match(subject):
                yield rdfvalue.URN().UnSerializeFromString(subject)

    def QueryPredicate(self, predicate):
        """Yields all subjects which have this predicate."""
        predicate = utils.SmartStr(predicate)
        for subject, data in six.iteritems(self.store):
            for pred, values in six.iteritems(data):
                if pred == predicate:
                    if type(values) != type([]):
                        values = [values]
                    for value in values:
                        yield (rdfvalue.URN().UnSerializeFromString(subject),
                               rdfvalue.URN().UnSerializeFromString(predicate),
                               value)


    def QueryPredicateObject(self, predicate, object):
        predicate = utils.SmartUnicode(predicate)
        for subject, data in list(self.store.items()):
            for pred, value in list(data.items()):
                if pred == predicate:
                    if type(value) != type([]):
                        value = [value]

                    if object in value:
                        yield rdfvalue.URN(subject)

    def QuerySubjectPredicate(self, subject, predicate):
        subject = utils.SmartUnicode(subject)
        predicate = utils.SmartUnicode(predicate)
        for s, data in six.iteritems(self.store):
            if s == subject:
                for pred, value in six.iteritems(data):
                    if pred == predicate:
                        if type(value) != type([]):
                            value = [value]

                        for o in value:
                            yield o

    def SelectSubjectsByPrefix(self, prefix):
        prefix = utils.SmartUnicode(prefix)
        for subject in self.store:
            if subject.startswith(prefix):
                yield rdfvalue.URN(subject)

    def QueryPredicatesBySubject(self, subject):
        subject = utils.SmartUnicode(subject)
        for pred, value in list(self.store.get(subject, {}).items()):
            yield (rdfvalue.URN().UnSerializeFromString(pred), value)
