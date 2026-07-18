"""Shared pytest fixtures/constants for the hashle test suite."""

from __future__ import annotations

from hashle.algorithms import ALGORITHMS

#: Algorithms that can be cross-checked against Python's own hashlib module.
#: (md4, sha0, tiger192v1/v2, whirlpool are not available in hashlib, so
#: they are instead checked against known-good test vectors -- see
#: test_known_vectors.py.)
HASHLIB_ALGORITHMS = {
    "md5": "md5",
    "ripemd160": "ripemd160",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha512": "sha512",
    "sm3": "sm3",
}

ALL_ALGORITHM_NAMES = sorted(ALGORITHMS)
