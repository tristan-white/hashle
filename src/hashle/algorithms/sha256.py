"""SHA-256 (FIPS 180-4)."""

from __future__ import annotations

from .base import HashAlgorithm
from ._util import MASK32, rotr32, words_to_bytes, bytes_to_words

_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


class SHA256(HashAlgorithm):
    name = "sha256"
    digest_size = 32
    block_size = 64
    length_size = 8
    little_endian = False
    pad_byte = 0x80

    def iv(self):
        return (
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
        )

    def compress(self, state, block):
        h0, h1, h2, h3, h4, h5, h6, h7 = state
        w = list(bytes_to_words(block, 4, little_endian=False))

        for i in range(16, 64):
            s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK32)

        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        for i in range(64):
            s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + s1 + ch + _K[i] + w[i]) & MASK32
            s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & MASK32

            h = g
            g = f
            f = e
            e = (d + temp1) & MASK32
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & MASK32

        return (
            (h0 + a) & MASK32,
            (h1 + b) & MASK32,
            (h2 + c) & MASK32,
            (h3 + d) & MASK32,
            (h4 + e) & MASK32,
            (h5 + f) & MASK32,
            (h6 + g) & MASK32,
            (h7 + h) & MASK32,
        )

    def state_to_bytes(self, state):
        return words_to_bytes(state, 4, little_endian=False)

    def bytes_to_state(self, data):
        return bytes_to_words(data, 4, little_endian=False)
