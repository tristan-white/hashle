"""MD4 (RFC 1320)."""

from __future__ import annotations

from .base import HashAlgorithm
from ._util import MASK32, rotl32, words_to_bytes, bytes_to_words

_ROUND1_SHIFTS = (3, 7, 11, 19)
_ROUND2_SHIFTS = (3, 5, 9, 13)
_ROUND3_SHIFTS = (3, 9, 11, 15)

_ROUND2_ORDER = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
_ROUND3_ORDER = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)


def _f(x, y, z):
    return (x & y) | (~x & z)


def _g(x, y, z):
    return (x & y) | (x & z) | (y & z)


def _h(x, y, z):
    return x ^ y ^ z


class MD4(HashAlgorithm):
    name = "md4"
    digest_size = 16
    block_size = 64
    length_size = 8
    little_endian = True
    pad_byte = 0x80

    def iv(self):
        return (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)

    def compress(self, state, block):
        a, b, c, d = state
        aa, bb, cc, dd = a, b, c, d
        x = bytes_to_words(block, 4, little_endian=True)

        # Round 1: k walks x[0..15] in order.
        for i in range(16):
            a = rotl32((a + _f(b, c, d) + x[i]) & MASK32, _ROUND1_SHIFTS[i % 4])
            a, b, c, d = d, a, b, c

        # Round 2: k walks columns of x, with an additive constant.
        for i, k in enumerate(_ROUND2_ORDER):
            a = rotl32((a + _g(b, c, d) + x[k] + 0x5A827999) & MASK32, _ROUND2_SHIFTS[i % 4])
            a, b, c, d = d, a, b, c

        # Round 3: k walks x in bit-reversed-pair order, different constant.
        for i, k in enumerate(_ROUND3_ORDER):
            a = rotl32((a + _h(b, c, d) + x[k] + 0x6ED9EBA1) & MASK32, _ROUND3_SHIFTS[i % 4])
            a, b, c, d = d, a, b, c

        return (
            (a + aa) & MASK32,
            (b + bb) & MASK32,
            (c + cc) & MASK32,
            (d + dd) & MASK32,
        )

    def state_to_bytes(self, state):
        return words_to_bytes(state, 4, little_endian=True)

    def bytes_to_state(self, data):
        return bytes_to_words(data, 4, little_endian=True)
