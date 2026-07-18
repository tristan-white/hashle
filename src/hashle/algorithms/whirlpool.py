"""Whirlpool (ISO/IEC 10118-3:2004).

The compression function directly mirrors ``processBuffer()`` in the
reference NESSIE/ISO Whirlpool implementation; the C0-C7 lookup tables and
round constants (``_whirlpool_sbox.py``) were transcribed verbatim from
that same reference source.
"""

from __future__ import annotations

from .base import HashAlgorithm
from ._util import MASK64, words_to_bytes, bytes_to_words
from . import _whirlpool_sbox as sbox

_ROUNDS = 10
_TABLES = (sbox.C0, sbox.C1, sbox.C2, sbox.C3, sbox.C4, sbox.C5, sbox.C6, sbox.C7)


def _byte(x: int, shift: int) -> int:
    return (x >> shift) & 0xFF


def _mix(words: list[int], round_key: int | None) -> list[int]:
    """One diffusion step: for each output word i, XOR one byte's worth of
    S-box lookup from words[i], words[i-1], ..., words[i-7] (mod 8)."""
    out = [0] * 8
    for i in range(8):
        acc = 0
        for j in range(8):
            shift = 56 - 8 * j
            acc ^= _TABLES[j][_byte(words[(i - j) % 8], shift)]
        out[i] = acc
    if round_key is not None:
        out[0] ^= round_key
    return out


class Whirlpool(HashAlgorithm):
    name = "whirlpool"
    digest_size = 64
    block_size = 64
    length_size = 32
    little_endian = False
    pad_byte = 0x80

    def iv(self):
        return (0, 0, 0, 0, 0, 0, 0, 0)

    def compress(self, state, block):
        block_words = list(bytes_to_words(block, 8, little_endian=False))

        k = list(state)
        cipher_state = [(block_words[i] ^ k[i]) & MASK64 for i in range(8)]

        for r in range(1, _ROUNDS + 1):
            k = _mix(k, sbox.RC[r])
            cipher_state = [v ^ kk for v, kk in zip(_mix(cipher_state, None), k)]

        return tuple(
            (state[i] ^ cipher_state[i] ^ block_words[i]) & MASK64 for i in range(8)
        )

    def state_to_bytes(self, state):
        return words_to_bytes(state, 8, little_endian=False)

    def bytes_to_state(self, data):
        return bytes_to_words(data, 8, little_endian=False)
