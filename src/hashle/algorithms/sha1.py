"""SHA-1 (FIPS 180-4) and SHA-0 (the original, withdrawn 1993 FIPS 180).

SHA-0 and SHA-1 share an identical structure; the only difference is that
SHA-1's message schedule rotates each expanded word left by one bit, a fix
introduced by NSA to correct a weakness in SHA-0. hash_extender exposes
SHA-0 as the ``sha`` hash type (see ``hash_types[]`` in
``hash_extender_engine.c``), so both are implemented here, controlled by
the ``_rotate_w`` class flag.
"""

from __future__ import annotations

from .base import HashAlgorithm
from ._util import MASK32, rotl32, words_to_bytes, bytes_to_words


class _SHA1Base(HashAlgorithm):
    digest_size = 20
    block_size = 64
    length_size = 8
    little_endian = False
    pad_byte = 0x80

    #: SHA-1 rotates each newly expanded schedule word left by 1; SHA-0 does not.
    _rotate_w = True

    def iv(self):
        return (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

    def compress(self, state, block):
        h0, h1, h2, h3, h4 = state
        w = list(bytes_to_words(block, 4, little_endian=False))

        for i in range(16, 80):
            value = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
            if self._rotate_w:
                value = rotl32(value, 1)
            w.append(value & MASK32)

        a, b, c, d, e = h0, h1, h2, h3, h4
        for i in range(80):
            if i < 20:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (rotl32(a, 5) + f + e + k + w[i]) & MASK32
            a, b, c, d, e = temp, a, rotl32(b, 30), c, d

        return (
            (h0 + a) & MASK32,
            (h1 + b) & MASK32,
            (h2 + c) & MASK32,
            (h3 + d) & MASK32,
            (h4 + e) & MASK32,
        )

    def state_to_bytes(self, state):
        return words_to_bytes(state, 4, little_endian=False)

    def bytes_to_state(self, data):
        return bytes_to_words(data, 4, little_endian=False)


class SHA1(_SHA1Base):
    name = "sha1"
    _rotate_w = True


class SHA0(_SHA1Base):
    name = "sha"
    _rotate_w = False
