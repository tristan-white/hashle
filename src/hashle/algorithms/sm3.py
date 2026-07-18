"""SM3 (Chinese national standard GB/T 32905-2016, similar in structure to SHA-256)."""

from __future__ import annotations

from .base import HashAlgorithm
from ._util import MASK32, rotl32, words_to_bytes, bytes_to_words


def _t(j: int) -> int:
    return 0x79CC4519 if j < 16 else 0x7A879D8A


def _ff(j, x, y, z):
    return (x ^ y ^ z) if j < 16 else ((x & y) | (x & z) | (y & z))


def _gg(j, x, y, z):
    return (x ^ y ^ z) if j < 16 else ((x & y) | (~x & z))


def _p0(x):
    return x ^ rotl32(x, 9) ^ rotl32(x, 17)


def _p1(x):
    return x ^ rotl32(x, 15) ^ rotl32(x, 23)


class SM3(HashAlgorithm):
    name = "sm3"
    digest_size = 32
    block_size = 64
    length_size = 8
    little_endian = False
    pad_byte = 0x80

    def iv(self):
        return (
            0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
            0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
        )

    def compress(self, state, block):
        v = list(state)
        w = list(bytes_to_words(block, 4, little_endian=False))

        for j in range(16, 68):
            x = w[j - 16] ^ w[j - 9] ^ rotl32(w[j - 3], 15)
            x = _p1(x) ^ rotl32(w[j - 13], 7) ^ w[j - 6]
            w.append(x & MASK32)

        w1 = [(w[j] ^ w[j + 4]) & MASK32 for j in range(64)]

        a, b, c, d, e, f, g, h = v
        for j in range(64):
            ss1 = rotl32((rotl32(a, 12) + e + rotl32(_t(j), j % 32)) & MASK32, 7)
            ss2 = ss1 ^ rotl32(a, 12)
            tt1 = (_ff(j, a, b, c) + d + ss2 + w1[j]) & MASK32
            tt2 = (_gg(j, e, f, g) + h + ss1 + w[j]) & MASK32
            d = c
            c = rotl32(b, 9)
            b = a
            a = tt1
            h = g
            g = rotl32(f, 19)
            f = e
            e = _p0(tt2)

        return tuple(
            (nv ^ ov) & MASK32 for nv, ov in zip((a, b, c, d, e, f, g, h), v)
        )

    def state_to_bytes(self, state):
        return words_to_bytes(state, 4, little_endian=False)

    def bytes_to_state(self, data):
        return bytes_to_words(data, 4, little_endian=False)
