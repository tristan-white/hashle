"""Tiger (Anderson & Biham, 1995), as implemented by hash_extender.

The compression function, S-boxes, and key schedule below are a direct
translation of ``TIGER_Transform()`` in ``hash_extender/tiger.c``; the
S-box tables in ``_tiger_sboxes.py`` were extracted verbatim from that
same file so the two stay in sync.

hash_extender exposes two padding variants that use the same compression
function: ``tiger192v1`` pads with a leading ``0x01`` byte (matching the
original Tiger reference implementation), while ``tiger192v2`` uses the
more common ``0x80`` bit-padding convention. See ``hash_append_data()`` in
``hash_extender_engine.c``, which special-cases ``tiger192v1``.
"""

from __future__ import annotations

from .base import HashAlgorithm
from ._util import MASK64, words_to_bytes, bytes_to_words
from . import _tiger_sboxes as sbox

_KEY_SCHEDULE_A5 = 0xA5A5A5A5A5A5A5A5
_KEY_SCHEDULE_01 = 0x0123456789ABCDEF


def _c1(x: int) -> int:
    return (
        sbox.T1[x & 0xFF]
        ^ sbox.T2[(x >> 16) & 0xFF]
        ^ sbox.T3[(x >> 32) & 0xFF]
        ^ sbox.T4[(x >> 48) & 0xFF]
    )


def _c2(x: int) -> int:
    return (
        sbox.T4[(x >> 8) & 0xFF]
        ^ sbox.T3[(x >> 24) & 0xFF]
        ^ sbox.T2[(x >> 40) & 0xFF]
        ^ sbox.T1[(x >> 56) & 0xFF]
    )


def _pass(a: int, b: int, c: int, x: list[int], mul: int) -> tuple[int, int, int]:
    regs = [a, b, c]
    # (p, q, r) rolls through (a, b, c), (b, c, a), (c, a, b) for the 8 words.
    order = ((0, 1, 2), (1, 2, 0), (2, 0, 1))
    for i in range(8):
        p, q, r = order[i % 3]
        regs[r] = (regs[r] ^ x[i]) & MASK64
        regs[p] = (regs[p] - _c1(regs[r])) & MASK64
        regs[q] = (regs[q] + _c2(regs[r])) & MASK64
        regs[q] = (regs[q] * mul) & MASK64
    return regs[0], regs[1], regs[2]


def _key_schedule(x: list[int]) -> None:
    x[0] = (x[0] - (x[7] ^ _KEY_SCHEDULE_A5)) & MASK64
    x[1] = (x[1] ^ x[0]) & MASK64
    x[2] = (x[2] + x[1]) & MASK64
    x[3] = (x[3] - (x[2] ^ (((~x[1]) & MASK64) << 19 & MASK64))) & MASK64
    x[4] = (x[4] ^ x[3]) & MASK64
    x[5] = (x[5] + x[4]) & MASK64
    x[6] = (x[6] - (x[5] ^ (((~x[4]) & MASK64) >> 23))) & MASK64
    x[7] = (x[7] ^ x[6]) & MASK64
    x[0] = (x[0] + x[7]) & MASK64
    x[1] = (x[1] - (x[0] ^ (((~x[7]) & MASK64) << 19 & MASK64))) & MASK64
    x[2] = (x[2] ^ x[1]) & MASK64
    x[3] = (x[3] + x[2]) & MASK64
    x[4] = (x[4] - (x[3] ^ (((~x[2]) & MASK64) >> 23))) & MASK64
    x[5] = (x[5] ^ x[4]) & MASK64
    x[6] = (x[6] + x[5]) & MASK64
    x[7] = (x[7] - (x[6] ^ _KEY_SCHEDULE_01)) & MASK64


class _TigerBase(HashAlgorithm):
    digest_size = 24
    block_size = 64
    length_size = 8
    little_endian = True

    def iv(self):
        return (0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xF096A5B4C3B2E187)

    def compress(self, state, block):
        a, b, c = state
        x = list(bytes_to_words(block, 8, little_endian=True))

        a, b, c = _pass(a, b, c, x, 5)
        _key_schedule(x)
        c, a, b = _pass(c, a, b, x, 7)
        _key_schedule(x)
        b, c, a = _pass(b, c, a, x, 9)

        return (state[0] ^ a, (b - state[1]) & MASK64, (state[2] + c) & MASK64)

    def state_to_bytes(self, state):
        return words_to_bytes(state, 8, little_endian=True)

    def bytes_to_state(self, data):
        return bytes_to_words(data, 8, little_endian=True)


class Tiger192v1(_TigerBase):
    name = "tiger192v1"
    pad_byte = 0x01


class Tiger192v2(_TigerBase):
    name = "tiger192v2"
    pad_byte = 0x80
