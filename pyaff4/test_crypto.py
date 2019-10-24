from future import standard_library
standard_library.install_aliases()
import os
import io
import unittest

import binascii
from pyaff4.aes_keywrap import aes_wrap_key, aes_unwrap_key
from passlib.crypto import digest
from CryptoPlus.Cipher import python_AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA1
from Crypto.Signature import pss
import codecs
import rdflib
from pyaff4 import keybag

referenceImagesPath = os.path.join(os.path.dirname(__file__), u"..",
                                   u"test_images")
cert = os.path.join(referenceImagesPath, u"keys", u"certificate.pem")
privateKey = os.path.join(referenceImagesPath, u"keys", u"key.pem")

keybagturtle = """
@prefix :      <aff4://685e15cc-d0fb-4dbc-ba47-48117fc77044> .
@prefix rdf:   <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix xsd:   <http://www.w3.org/2001/XMLSchema#> .
@prefix aff4:  <http://aff4.org/Schema#> .

<aff4://c21070c3-6d57-4f3b-9276-f83b6bfed5ae>
    a   aff4:KeyBag ;
    aff4:wrappedKey "5934f7d07e75f5ab55b9051ebd39331dbfba3c597589b203728043577bf93badeb9f07f528c8bd95"^^xsd:hexBinary ;
    aff4:salt   "000102030405060708090a0b0c0d0e0f"^^xsd:hexBinary ;
    aff4:iterations 147256 ;
    aff4:keySizeInBytes 32 .
"""

src = "I am happy to join with you today in what will go down in history as the greatest demonstration for freedom in the history of our nation.".encode()

target_ciphertext = binascii.unhexlify(
    "0c2e8b50c053afa8b09331096241490a6ab339f39f6530491bbbb6a75d46d6bc188fcda8e4b72c763e7dc7f55335f" +
    "909be8a049267f7c2e26189a352b7466520e6af498e9d674e99efd8753f1a46733072dfbb43a1665f1aec207bfc023998edc3ff0d9ca1" +
    "42013e7cfef85236649e0b4ae51b6a4758742bb4b17ec6e2cd47235e41739e464c5128c466c4d6f16d97724ebc764b1f91bb28313d3e2" +
    "8e3a54d73543f173d93c9b4cbba16d8bca5300095d0412057118551d9adb5142a5c3b4e0ab12f4858c608165eb24891e8e815a3815c06" +
    "9cce94ce75f018a01856a01e0a952e1d8015fb46ca80fd0fb17f2a9c348be6a86be3a202a7dec76ef04e7e04483eb9ccd2dbcf7943e59" +
    "0c7c03e2e0ed297b08a09984ff9f9c89c32c0fdcd8f814e8e9d4b39c1bf082b2f1a0f852dc3f48fc014b2300e75c85d6ce7f4ef3c5afa" +
    "cbf49ba2e00288a23e57196dc3558821578a9e452a687eb7b53b3477d3eda4c6febbbec59fc7bef46cbad3abbc6b4aefaf9aeb6b935ba" +
    "55afc2747ad4fe53ddcfed77caaa2628ce0aa4d836703d134ace22d9c6ac0f9d65113c21e05d49913ba6650ca3c1a34640a876218de50" +
    "f07cf743ff8902c456ae7ef8cee28ec0e0c5dbdcdce173dde8bb80f69d84a38a4cd580149100a144cbe844f9fe355186654ab525b28db" +
    "411c49d4c96b84670471f60765d048e03178663b4fec9d9bb05835c52f7")

class CryptoTest(unittest.TestCase):

    def testCreateWrappedKey(self):
        wrapped = binascii.unhexlify("5934f7d07e75f5ab55b9051ebd39331dbfba3c597589b203728043577bf93badeb9f07f528c8bd95")
        g = rdflib.Graph()
        g.parse(data=keybagturtle, format="turtle")

        kb = keybag.PasswordWrappedKeyBag.load(g)
        self.assertEquals(wrapped, kb.wrappedKey)

    def testExtractWrappedKey(self):
        wrapped = binascii.unhexlify("5934f7d07e75f5ab55b9051ebd39331dbfba3c597589b203728043577bf93badeb9f07f528c8bd95")
        target_kek = binascii.unhexlify("9bc68a8c80a008d758de97cebc7ec39d6274512e3ddbdd5baf4eb8557ab7e58f")
        target_vek = binascii.unhexlify("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

        g = rdflib.Graph()
        g.parse(data=keybagturtle, format="turtle")
        kb = keybag.PasswordWrappedKeyBag.load(g)

        key = "password"
        kek = digest.pbkdf2_hmac("sha256", key, kb.salt, kb.iterations, kb.keySizeBytes);
        self.assertEquals(target_kek, kek)
        vek = aes_unwrap_key(kek, kb.wrappedKey)
        self.assertEquals(target_vek, vek)

    def testEncrypt(self):
        vek = binascii.unhexlify("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        plaintext = src + b'\x00' * (512-len(src))

        key1 = vek[0:16]
        key2 = vek[16:]

        tweak = codecs.decode('00', 'hex')

        cipher = python_AES.new((key1,key2), python_AES.MODE_XTS)
        ciphertext = cipher.encrypt(plaintext, tweak)

        self.assertEqual(target_ciphertext, ciphertext)

    def testDecrypt(self):

        g = rdflib.Graph()
        g.parse(data=keybagturtle, format="turtle")
        kb = keybag.PasswordWrappedKeyBag.load(g)

        key = "password"
        kek = digest.pbkdf2_hmac("sha256", key, kb.salt, kb.iterations, kb.keySizeBytes);
        vek = aes_unwrap_key(kek, kb.wrappedKey)

        key1 = vek[0:16]
        key2 = vek[16:]
        tweak = codecs.decode('00', 'hex')

        cipher = python_AES.new((key1, key2), python_AES.MODE_XTS)
        text = cipher.decrypt(target_ciphertext, tweak)

        self.assertEqual(src[0:len(src)], text[0:len(src)])


    def testWrap(self):
        keysize = 0x20   # in bytes
        key = "password"
        iterations = 147256
        saltSize = 16
        salt = binascii.unhexlify("000102030405060708090a0b0c0d0e0f")


        #hhh = hashlib.pbkdf2_hmac("sha256", key.encode(), salt, iterations, keysize);
        #print(len(hhh))
        #print(binascii.hexlify(hhh))

        kek = digest.pbkdf2_hmac("sha256", key, salt, iterations, keysize);
        print(binascii.hexlify(kek))

        #h = pbkdf2_sha256.encrypt(key, rounds=iterations, salt_size=saltSize)
        # print(h)



        vek = binascii.unhexlify("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        print(len(vek))
        wrapped_key= aes_wrap_key(kek, vek)
        print(binascii.hexlify(wrapped_key))

        plaintext = src + b'\x00' * (512-len(src))

        #msg = dict_xts_aes['msg%i' % i].decode('hex')
        #key = (dict_xts_aes['key1_%i' % i].decode('hex'), dict_xts_aes['key2_%i' % i].decode('hex'))
        key1 = vek[0:16]
        key2 = vek[16:]
        #cip = dict_xts_aes['cip%i' % i].decode('hex')
        #n = dict_xts_aes['n%i' % i].decode('hex')
        tweak = codecs.decode('00', 'hex')
        print(len(tweak))
        cipher = python_AES.new((key1,key2), python_AES.MODE_XTS)
        ciphertext = cipher.encrypt(plaintext, tweak)

        print(len(ciphertext))
        print(binascii.hexlify(ciphertext))

    def testPKIWrap(self):
        vek = binascii.unhexlify("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

        publicKey = RSA.importKey(open(cert).read())
        cipher = PKCS1_OAEP.new(key=publicKey, hashAlgo=SHA256, mgfunc=lambda x, y: pss.MGF1(x, y, SHA1))
        ciphertext = cipher.encrypt(vek)

        key = RSA.importKey(open(privateKey).read())
        cipher = PKCS1_OAEP.new(key=key, hashAlgo=SHA256, mgfunc=lambda x, y: pss.MGF1(x, y, SHA1))
        vek2 = cipher.decrypt(ciphertext)
        self.assertEquals(vek, vek2)

