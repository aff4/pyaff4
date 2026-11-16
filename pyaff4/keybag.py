# Copyright 2019 Schatz Forensic Pty Ltd All rights reserved.
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
#
# Author: Bradley L Schatz bradley@evimetry.com

import binascii, rdflib
from passlib.crypto import digest
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap, aes_key_wrap
from pyaff4 import aff4, lexicon
from rdflib import Literal, XSD
from rdflib.namespace import RDF
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA1
from Crypto.Signature import pss
from cryptography import x509

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
        kek = digest.pbkdf2_hmac("sha256", password, salt, iterations, keysize)
        wrapped_key = aes_key_wrap(kek, vek)
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
        kek = digest.pbkdf2_hmac("sha256", password, self.salt, self.iterations, self.keySizeBytes)
        try:
            vek = aes_key_unwrap(kek, self.wrappedKey)
        except InvalidUnwrap as e:
            raise ValueError(
                f"cannot unwrap key bag {self.ID}: RFC 3394 integrity check failed "
                "(wrong password?)"
            ) from e
        #print("VEK: " + str(binascii.hexlify(vek)))
        return vek

    def write(self, resolver, volumeARN):
        resolver.Add(volumeARN, self.ID, lexicon.AFF4_TYPE, lexicon.AFF4_PASSWORD_WRAPPED_KEYBAG)
        resolver.Set(volumeARN, self.ID, lexicon.AFF4_KEYSIZEBYTES, Literal(self.keySizeBytes, datatype=XSD.integer))
        resolver.Set(volumeARN, self.ID, lexicon.AFF4_ITERATIONS, Literal(self.iterations, datatype=XSD.integer))
        resolver.Set(volumeARN, self.ID, lexicon.AFF4_WRAPPEDKEY, Literal(binascii.hexlify(self.wrappedKey), datatype=XSD.hexBinary))
        resolver.Set(volumeARN, self.ID, lexicon.AFF4_SALT, Literal(binascii.hexlify(self.salt), datatype=XSD.hexBinary))

    @staticmethod
    def loadFromResolver(resolver, volumeARN, keyBagARN):
        salt = resolver.GetUnique(volumeARN, keyBagARN, lexicon.standard11.salt)
        iterations = resolver.GetUnique(volumeARN, keyBagARN, lexicon.standard11.iterations)
        keySizeInBytes = resolver.GetUnique(volumeARN, keyBagARN, lexicon.standard11.keySizeInBytes)
        wrappedKey = resolver.GetUnique(volumeARN, keyBagARN, lexicon.standard11.wrappedKey)
        #print("WrappedKey: " + str(binascii.hexlify(wrappedKey.value)))
        return PasswordWrappedKeyBag(salt.toPython(), iterations.toPython(), keySizeInBytes.toPython(), wrappedKey.toPython())

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
        with open(certificatePath) as f:
            publicKeyPem = f.read()
        publicKey = RSA.importKey(publicKeyPem)

        cert = x509.load_pem_x509_certificate(publicKeyPem.encode("utf-8"))
        subjectName = cert.subject.rfc4514_string()
        serial = cert.serial_number

        cipher = PKCS1_OAEP.new(key=publicKey, hashAlgo=SHA256, mgfunc=lambda x, y: pss.MGF1(x, y, SHA1))
        wrapped_key = cipher.encrypt(vek)
        #print("WrappedKey: " + str(binascii.hexlify(wrapped_key)))

        return CertEncryptedKeyBag(subjectName, serial, keySizeBytes, wrapped_key)


    def unwrap_key(self, privateKey):
        with open(privateKey) as f:
            key = RSA.importKey(f.read())
        cipher = PKCS1_OAEP.new(key=key, hashAlgo=SHA256, mgfunc=lambda x, y: pss.MGF1(x, y, SHA1))
        vek = cipher.decrypt(self.wrappedKey)
        #print("VEK: " + str(binascii.hexlify(vek)))
        return vek

    def write(self, resolver, volumeARN):
        resolver.Add(volumeARN, self.ID, lexicon.AFF4_TYPE, lexicon.AFF4_CERT_ENCRYPTED_KEYBAG)
        resolver.Set(volumeARN, self.ID, lexicon.AFF4_KEYSIZEBYTES, Literal(self.keySizeBytes, datatype=XSD.integer))
        resolver.Set(volumeARN, self.ID, lexicon.AFF4_SERIALNUMBER, Literal(self.serialNumber, datatype=XSD.integer))
        resolver.Set(volumeARN, self.ID, lexicon.AFF4_WRAPPEDKEY, Literal(binascii.hexlify(self.wrappedKey), datatype=XSD.hexBinary))
        resolver.Set(volumeARN, self.ID, lexicon.AFF4_SUBJECTNAME, Literal(self.subjectName))


    @staticmethod
    def loadFromResolver(resolver, volumeARN, keyBagARN):
        subjectName = resolver.GetUnique(volumeARN, keyBagARN, lexicon.standard11.subjectName)
        serial = resolver.GetUnique(volumeARN, keyBagARN, lexicon.standard11.serialNumber)
        keySizeInBytes = resolver.GetUnique(volumeARN, keyBagARN, lexicon.standard11.keySizeInBytes)
        wrappedKey = resolver.GetUnique(volumeARN, keyBagARN, lexicon.standard11.wrappedKey)
        #print("WrappedKey: " + str(binascii.hexlify(wrappedKey.value)))
        return CertEncryptedKeyBag(subjectName.toPython(), serial.toPython(), keySizeInBytes.toPython(), wrappedKey.toPython())
