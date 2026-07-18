"""Small shared helpers for packing/unpacking hash state words."""

from __future__ import annotations

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF


def rotl32(x: int, n: int) -> int:
    x &= MASK32
    return ((x << n) | (x >> (32 - n))) & MASK32


def rotr32(x: int, n: int) -> int:
    x &= MASK32
    return ((x >> n) | (x << (32 - n))) & MASK32


def rotl64(x: int, n: int) -> int:
    x &= MASK64
    return ((x << n) | (x >> (64 - n))) & MASK64


def rotr64(x: int, n: int) -> int:
    x &= MASK64
    return ((x >> n) | (x << (64 - n))) & MASK64


def words_to_bytes(words: tuple, word_size: int, little_endian: bool) -> bytes:
    """Pack a tuple of unsigned integers into bytes.

    :param word_size: size of each word in bytes (4 for 32-bit, 8 for 64-bit).
    """
    order = "little" if little_endian else "big"
    return b"".join(w.to_bytes(word_size, order) for w in words)


def bytes_to_words(data: bytes, word_size: int, little_endian: bool) -> tuple:
    order = "little" if little_endian else "big"
    return tuple(
        int.from_bytes(data[i : i + word_size], order)
        for i in range(0, len(data), word_size)
    )
