"""Verify every hashle algorithm implementation against hashlib.

Modeled on hlextend/hlextend_testscript.py's "comparative hash generation
test": for every algorithm that Python's hashlib also implements, hash
strings of every length from 0 to 255 bytes and confirm the digests match
exactly.
"""

from __future__ import annotations

import hashlib

import pytest

from hashle.algorithms import get_algorithm

from .conftest import HASHLIB_ALGORITHMS


@pytest.mark.parametrize("hashle_name,hashlib_name", sorted(HASHLIB_ALGORITHMS.items()))
def test_matches_hashlib_across_lengths(hashle_name: str, hashlib_name: str) -> None:
    cls = get_algorithm(hashle_name)
    for length in range(0, 256):
        data = b"A" * length
        expected = hashlib.new(hashlib_name, data).hexdigest()
        actual = cls().hash(data).hexdigest()
        assert actual == expected, f"{hashle_name} mismatch at length {length}"


@pytest.mark.parametrize("hashle_name,hashlib_name", sorted(HASHLIB_ALGORITHMS.items()))
def test_matches_hashlib_reference_strings(hashle_name: str, hashlib_name: str) -> None:
    references = [
        b"abc",
        b"The quick brown fox jumped over the lazy dog",
        b"The quick brown fox jumped over the lazy dog.",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    ]
    cls = get_algorithm(hashle_name)
    for ref in references:
        expected = hashlib.new(hashlib_name, ref).hexdigest()
        actual = cls().hash(ref).hexdigest()
        assert actual == expected
