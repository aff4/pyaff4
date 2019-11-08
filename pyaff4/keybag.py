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

from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals

from builtins import next
from builtins import str
from builtins import object
import binascii, rdflib, os
from passlib.crypto import digest
from pyaff4.aes_keywrap import aes_wrap_key, aes_unwrap_key
from pyaff4.utils import SmartStr
from pyaff4 import aff4, lexicon, rdfvalue
from rdflib import URIRef
from rdflib.namespace import RDF
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA1
from Crypto.Signature import pss
from cryptography import x509
from cryptography.hazmat.backends import default_backend

keysize = 0x20  # in bytes
iterations = 147256
saltSize = 16

class PasswordWrappedKeyBag:
    def __init__(self, salt, iterations, keySizeBytes, wrappedKey):
        self.salt = salt
        self.iterations = iterations
        self.keySizeBytes = keySizeBytes
        self.wrappedKey = wrappedKey
        self.ID = aff4.newARN()

    @staticmethod
    def create(password):
        salt = Random.get_random_bytes(saltSize)
        vek = Random.get_random_bytes(keysize)
        #print("VEK: " + str(binascii.hexlify(vek)))
        kek = digest.pbkdf2_hmac("sha256", password, salt, iterations, keysize);
        wrapped_key = aes_wrap_key(kek, vek)
        #print("WrappedKey: " + str(binascii.hexlify(wrapped_key)))
        return PasswordWrappedKeyBag(salt, iterations, keysize, wrapped_key)

    @staticmethod
    def load(graph):
        for kb, p, o in graph.triples((None, RDF.type, rdflib.URIRef("http://aff4.org/Schema#KeyBag"))):
            wk = graph.value(kb, rdflib.URIRef("http://aff4.org/Schema#wrappedKey"), None)
            salt = graph.value(kb, rdflib.URIRef("http://aff4.org/Schema#salt"), None)
            iterations = graph.value(kb, rdflib.URIRef("http://aff4.org/Schema#iterations"), None)
            keySizeInBytes = graph.value(kb, rdflib.URIRef("http://aff4.org/Schema#keySizeInBytes"), None)
            return PasswordWrappedKeyBag(salt._value, iterations._value, keySizeInBytes._value, wk._value)

    def unwrap_key(self, password):
        kek = digest.pbkdf2_hmac("sha256", password, self.salt, self.iterations, self.keySizeBytes);
        vek = aes_unwrap_key(kek, self.wrappedKey)
        #print("VEK: " + str(binascii.hexlify(vek)))
        return vek

    def write(self, resolver, volumeARN):
        resolver.Add(volumeARN, self.ID, lexicon.AFF4_TYPE, rdfvalue.URN(lexicon.AFF4_PASSWORD_WRAPPED_KEYBAG))
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
        #print("WrappedKey: " + str(binascii.hexlify(wrappedKey.value)))
        return PasswordWrappedKeyBag(salt.value, iterations.value, keySizeInBytes.value, wrappedKey.value)

class CertEncryptedKeyBag:
    def __init__(self, subjectName, serialNumber, keySizeBytes, wrappedKey):
        self.subjectName = subjectName
        self.serialNumber = serialNumber
        self.keySizeBytes = keySizeBytes
        self.wrappedKey = wrappedKey
        self.ID = aff4.newARN()


    @staticmethod
    def create(vek, keySizeBytes, certificatePath):
        #print("VEK: " + str(binascii.hexlify(vek)))
        publicKeyPem = open(certificatePath).read()
        publicKey = RSA.importKey(publicKeyPem)
        # Convert from PEM to DER

        lines = publicKeyPem.replace(" ", '').split()
        publicKeyDer = binascii.a2b_base64(''.join(lines[1:-1]))

        cert = x509.load_pem_x509_certificate(SmartStr(publicKeyPem), default_backend())
        subjectName = cert.subject.rfc4514_string()
        serial = cert.serial_number

        cipher = PKCS1_OAEP.new(key=publicKey, hashAlgo=SHA256, mgfunc=lambda x, y: pss.MGF1(x, y, SHA1))
        wrapped_key = cipher.encrypt(vek)
        #print("WrappedKey: " + str(binascii.hexlify(wrapped_key)))

        return CertEncryptedKeyBag(subjectName, serial, keySizeBytes, wrapped_key)


    def unwrap_key(self, privateKey):
        key = RSA.importKey(open(privateKey).read())
        cipher = PKCS1_OAEP.new(key=key, hashAlgo=SHA256, mgfunc=lambda x, y: pss.MGF1(x, y, SHA1))
        vek = cipher.decrypt(self.wrappedKey)
        #print("VEK: " + str(binascii.hexlify(vek)))
        return vek

    def write(self, resolver, volumeARN):
        resolver.Add(volumeARN, self.ID, lexicon.AFF4_TYPE, rdfvalue.URN(lexicon.AFF4_CERT_ENCRYPTED_KEYBAG))
        resolver.Set(volumeARN, self.ID, lexicon.AFF4_KEYSIZEBYTES, rdfvalue.XSDInteger(self.keySizeBytes))
        resolver.Set(volumeARN, self.ID, lexicon.AFF4_SERIALNUMBER, rdfvalue.XSDInteger(self.serialNumber))
        resolver.Set(volumeARN, self.ID, lexicon.AFF4_WRAPPEDKEY, rdfvalue.RDFBytes(self.wrappedKey))
        resolver.Set(volumeARN, self.ID, lexicon.AFF4_SUBJECTNAME, rdfvalue.XSDString(self.subjectName))


    @staticmethod
    def loadFromResolver(resolver, volumeARN, keyBagARN):
        subjectName = resolver.GetUnique(volumeARN, keyBagARN, lexicon.standard11.subjectName)
        serial = resolver.GetUnique(volumeARN, keyBagARN, lexicon.standard11.serialNumber)
        keySizeInBytes = resolver.GetUnique(volumeARN, keyBagARN, lexicon.standard11.keySizeInBytes)
        wrappedKey = resolver.GetUnique(volumeARN, keyBagARN, lexicon.standard11.wrappedKey)
        #print("WrappedKey: " + str(binascii.hexlify(wrappedKey.value)))
        return CertEncryptedKeyBag(subjectName.value, serial.value, keySizeInBytes.value, wrappedKey.value)
