# Copyright 2015 Google Inc. All rights reserved.
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
from rdflib import URIRef, XSD, RDF, Literal

from pyaff4.rdfvalue import ARN, FileRef

from pyaff4 import aff4
from pyaff4 import data_store
from pyaff4 import lexicon
from pyaff4 import rdfvalue
from pyaff4 import streams
import unittest

import io


class DataStoreTest(unittest.TestCase):
    def setUp(self):
        self.hello_urn = ARN("aff4://hello")
        self.store = data_store.MemoryDataStore()
        self.store.Set(None,
            self.hello_urn, lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY,
            Literal("foo"))

        self.store.Set(None,
            self.hello_urn, lexicon.AFF4_TYPE,
            Literal("bar"))

    def testDataStore(self):
        result = self.store.GetUnique(None, self.hello_urn, lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY)
        self.assertEqual(type(result), Literal)

        self.assertEqual(result.toPython(), "foo")

        self.store.Set(None,
            self.hello_urn, lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY,
            Literal("bar"))

        # In the current implementation a second Set() overwrites the previous
        # value.
        self.assertEqual(
            self.store.GetUnique(None,self.hello_urn, lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY),
            Literal("bar"))

    def testTurtleSerialization(self):
        data = self.store._DumpToTurtle(None, verbose=True)
        new_store = data_store.MemoryDataStore()
        stream = io.BytesIO(data.encode('utf-8'))
        new_store.LoadFromTurtle(stream, None)
        res = new_store.GetUnique(None,self.hello_urn,
            lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY)
        self.assertEqual(res.toPython(), "foo")

    def testARNSearch2(self):
        store = data_store.MemoryDataStore()
        store.Add(ARN("aff4://b40aa9b3-bfff-47f3-af29-1d729f0a687d/image.dd"),
                  ARN("aff4://b40aa9b3-bfff-47f3-af29-1d729f0a687d/image.dd"),
                  URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
                  URIRef("http://example1"))
        for (s,p,o) in store.transient_store.triples((None, None, None)):
            self.assertEqual(ARN("aff4://b40aa9b3-bfff-47f3-af29-1d729f0a687d/image.dd"), s)
            self.assertEqual("http://www.w3.org/1999/02/22-rdf-syntax-ns#type", str(RDF.type))

        for (s,p,o) in store.transient_store.triples((ARN("aff4://b40aa9b3-bfff-47f3-af29-1d729f0a687d/image.dd"),
                                                      URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
                                                      None)):
            self.assertEqual(ARN("aff4://b40aa9b3-bfff-47f3-af29-1d729f0a687d/image.dd"), s)
            self.assertEqual("http://www.w3.org/1999/02/22-rdf-syntax-ns#type", str(RDF.type))

        for o in store.Get(lexicon.any,
                           ARN("aff4://b40aa9b3-bfff-47f3-af29-1d729f0a687d/image.dd"),
                            URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type") ):
            self.assertEqual(URIRef("http://example1"), o)

        res = store.Get(lexicon.any,
                           ARN("aff4://b40aa9b3-bfff-47f3-af29-1d729f0a687d/image.dd"),
                           URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type") )
        for o in res:
            self.assertEqual(URIRef("http://example1"), o)

    def testARNSearch(self):
        store = data_store.MemoryDataStore()
        store.Add(ARN("aff4://b40aa9b3-bfff-47f3-af29-1d729f0a687d/image.dd"),
                  ARN("aff4://b40aa9b3-bfff-47f3-af29-1d729f0a687d/image.dd"),
                  URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
                  URIRef("http://example1"))
        store.Add(ARN("aff4://b40aa9b3-bfff-47f3-af29-1d729f0a687d/image.dd"),
                  ARN("aff4://b40aa9b3-bfff-47f3-af29-1d729f0a687d/image.dd"),
                  URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
                  URIRef("http://example1"))
        for (s,p,o) in store.transient_store.triples((None, None, None)):
            self.assertEqual(ARN("aff4://b40aa9b3-bfff-47f3-af29-1d729f0a687d/image.dd"), s)
            self.assertTrue(isinstance(s, ARN))
            self.assertEqual("http://www.w3.org/1999/02/22-rdf-syntax-ns#type", str(RDF.type))

        for (s,p,o) in store.transient_store.triples((ARN("aff4://b40aa9b3-bfff-47f3-af29-1d729f0a687d/image.dd"),
                                                      URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
                                                      None)):
            self.assertEqual(ARN("aff4://b40aa9b3-bfff-47f3-af29-1d729f0a687d/image.dd"), s)
            self.assertEqual("http://www.w3.org/1999/02/22-rdf-syntax-ns#type", str(RDF.type))

        for o in store.Get(lexicon.any,
                           ARN("aff4://b40aa9b3-bfff-47f3-af29-1d729f0a687d/image.dd"),
                           URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type") ):
            self.assertEqual(URIRef("http://example1"), o)

        res = store.Get(lexicon.any,
                        ARN("aff4://b40aa9b3-bfff-47f3-af29-1d729f0a687d/image.dd"),
                        URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type") )
        for o in res:
            self.assertEqual(URIRef("http://example1"), o)


class AFF4ObjectCacheMock(data_store.AFF4ObjectCache):
    def GetKeys(self):
        return [entry.key for entry in self.lru_list]

    def GetInUse(self):
        return [key for key in self.in_use]


class AFF4ObjectCacheTest(unittest.TestCase):
    def testLRU(self):
        cache = AFF4ObjectCacheMock(3)
        resolver = data_store.MemoryDataStore()

        obj1 = aff4.AFF4Object(resolver, rdfvalue.URN.FromFileName("/a"), None)
        obj2 = aff4.AFF4Object(resolver, rdfvalue.URN.FromFileName("/b"), None)
        obj3 = aff4.AFF4Object(resolver, rdfvalue.URN.FromFileName("/c"), None)
        obj4 = aff4.AFF4Object(resolver, rdfvalue.URN.FromFileName("/d"), None)

        cache.Put(obj1)
        cache.Put(obj2)
        cache.Put(obj3)

        result = cache.GetKeys()

        # Keys are stored as serialized urns.
        self.assertEqual(result[0], "file:///c")
        self.assertEqual(result[1], "file:///b")
        self.assertEqual(result[2], "file:///a")

        # This removes the object from the cache and places it in the in_use
        # list.
        self.assertEqual(cache.Get(FileRef("file:///a")), obj1)

        # Keys are stored as serialized urns.
        result = cache.GetKeys()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], "file:///c")
        self.assertEqual(result[1], "file:///b")

        # Keys are stored as serialized urns.
        in_use = cache.GetInUse()
        self.assertEqual(len(in_use), 1)
        self.assertEqual(in_use[0], "file:///a")

        # Now we return the object. It should now appear in the lru lists.
        cache.Return(obj1)

        result = cache.GetKeys()
        self.assertEqual(len(result), 3)

        self.assertEqual(result[0], "file:///a")
        self.assertEqual(result[1], "file:///c")
        self.assertEqual(result[2], "file:///b")

        in_use = cache.GetInUse()
        self.assertEqual(len(in_use), 0)

        # Over flow the cache - this should expire the older object.
        cache.Put(obj4)
        result = cache.GetKeys()
        self.assertEqual(len(result), 3)

        self.assertEqual(result[0], "file:///d")
        self.assertEqual(result[1], "file:///a")
        self.assertEqual(result[2], "file:///c")

        # b is now expired so not in cache.
        self.assertEqual(cache.Get(FileRef("file:///b")), None)

        # Check that remove works
        cache.Remove(obj4)

        self.assertEqual(cache.Get(FileRef("file:///d")), None)
        result = cache.GetKeys()
        self.assertEqual(len(result), 2)


if __name__ == '__main__':
    unittest.main()
