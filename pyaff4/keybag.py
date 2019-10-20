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
import binascii, rdflib, os
from passlib.crypto import digest
from pyaff4.aes_keywrap import aes_wrap_key, aes_unwrap_key
from pyaff4 import aff4, lexicon, rdfvalue
from rdflib import URIRef
from rdflib.namespace import RDF

_XSD_PFX = 'http://www.w3.org/2001/XMLSchema#'
rdflib.term._toPythonMapping[URIRef(_XSD_PFX + 'hexBinary')] = lambda s: binascii.unhexlify(s)

keysize = 0x20  # in bytes
iterations = 147256
saltSize = 16
#keysize = 32

class KeyBag:
    def __init__(self, salt, iterations, keySizeBytes, wrappedKey):
        self.salt = salt
        self.iterations = iterations
        self.keySizeBytes = keySizeBytes
        self.wrappedKey = wrappedKey
        self.ID = aff4.newARN()

    @staticmethod
    def create(password):
        #salt = binascii.unhexlify("000102030405060708090a0b0c0d0e0f")
        #vek = binascii.unhexlify("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        salt = os.urandom(saltSize)
        vek = os.urandom(keysize)
        print("VEK: " + str(binascii.hexlify(vek)))
        kek = digest.pbkdf2_hmac("sha256", password, salt, iterations, keysize);
        wrapped_key = aes_wrap_key(kek, vek)
        print("WrappedKey: " + str(binascii.hexlify(wrapped_key)))
        return KeyBag(salt, iterations, keysize, wrapped_key)

    @staticmethod
    def load(graph):
        for kb, p, o in graph.triples((None, RDF.type, rdflib.URIRef("http://aff4.org/Schema#KeyBag"))):
            wk = graph.value(kb, rdflib.URIRef("http://aff4.org/Schema#wrappedKey"), None)
            salt = graph.value(kb, rdflib.URIRef("http://aff4.org/Schema#salt"), None)
            iterations = graph.value(kb, rdflib.URIRef("http://aff4.org/Schema#iterations"), None)
            keySizeInBytes = graph.value(kb, rdflib.URIRef("http://aff4.org/Schema#keySizeInBytes"), None)
            return KeyBag(salt._value, iterations._value, keySizeInBytes._value, wk._value)

    def unwrap_key(self, password):
        kek = digest.pbkdf2_hmac("sha256", password, self.salt, self.iterations, self.keySizeBytes);
        vek = aes_unwrap_key(kek, self.wrappedKey)
        print("VEK: " + str(binascii.hexlify(vek)))
        return vek

    def write(self, resolver, volumeARN):
        resolver.Add(volumeARN, self.ID, lexicon.AFF4_TYPE, rdfvalue.URN(lexicon.AFF4_KEYBAG))
        resolver.Set(volumeARN, self.ID, lexicon.AFF4_KEYSIZEBYTES, rdfvalue.XSDInteger(self.keySizeBytes))
        resolver.Set(volumeARN, self.ID, lexicon.AFF4_ITERATIONS, rdfvalue.XSDInteger(self.iterations))
        resolver.Set(volumeARN, self.ID, lexicon.AFF4_WRAPPEDKEY, rdfvalue.RDFBytes(self.wrappedKey))
        resolver.Set(volumeARN, self.ID, lexicon.AFF4_SALT, rdfvalue.RDFBytes(self.salt))

    @staticmethod
    def loadFromResolver(resolver, volumeARN, keyBagARN):
        salt = resolver.GetUnique(volumeARN, keyBagARN, lexicon.standard11.salt)
        iterations = resolver.GetUnique(volumeARN, keyBagARN, lexicon.standard11.iterations)
        keySizeInBytes = resolver.GetUnique(volumeARN, keyBagARN, lexicon.standard11.keySizeInBytes)
        wrappedKey = resolver.GetUnique(volumeARN, keyBagARN, lexicon.standard11.wrappedKey)
        print("WrappedKey: " + str(binascii.hexlify(wrappedKey.value._value)))
        return KeyBag(salt.value._value, iterations.value, keySizeInBytes.value, wrappedKey.value._value)