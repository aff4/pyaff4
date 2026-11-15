#
# Copyright © 2026 Apple Inc.
#
# Licensed under Apache License v2.0
# SPDX-License-Identifier: Apache-2.0
#

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _pad_tweak(tweak: bytes) -> bytes:
    if len(tweak) > 16:
        raise ValueError(f"XTS tweak must be at most 16 bytes, got {len(tweak)}")
    return tweak + b"\x00" * (16 - len(tweak))


class AesXts:
    """AES-XTS cipher matching pycryptoplus's tweak-handling.

    AFF4 encrypted streams write an 8-byte little-endian chunk-address
    tweak; AES-XTS requires 16. pycryptoplus zero-pads on the right;
    this class does the same so on-disk ciphertext stays byte-identical.
    """

    def __init__(self, key1: bytes, key2: bytes) -> None:
        self._key = key1 + key2

    def encrypt(self, data: bytes, tweak: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self._key), modes.XTS(_pad_tweak(tweak)))
        return cipher.encryptor().update(data)

    def decrypt(self, data: bytes, tweak: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self._key), modes.XTS(_pad_tweak(tweak)))
        return cipher.decryptor().update(data)


def new(keys: tuple[bytes, bytes]) -> AesXts:
    key1, key2 = keys
    return AesXts(key1, key2)
