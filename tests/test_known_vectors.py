"""Known-vector tests for algorithms not available via hashlib.

md4, sha (sha0), tiger192v1, tiger192v2 and whirlpool are not implemented
by Python's hashlib, so instead of comparing against hashlib they are
checked here against published, independently-sourced test vectors.
"""

from __future__ import annotations

import pytest

from hashle.algorithms import get_algorithm

# RFC 1320 test vectors.
MD4_VECTORS = [
    (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
    (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
    (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
    (b"message digest", "d9130a8164549fe818874806e1c7014b"),
    (b"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
]

# FIPS 180 (the withdrawn original SHA, commonly called SHA-0) test vectors.
SHA0_VECTORS = [
    (b"", "f96cea198ad1dd5617ac084a3d92c6107708c0ef"),
    (b"abc", "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880"),
]

# Cross-checked against hash_extender/tiger.c (the C reference this
# implementation was ported from) compiled and run directly.
TIGER192V1_VECTORS = [
    (b"", "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3"),
    (b"abc", "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93"),
    (b"Tiger", "dd00230799f5009fec6debc838bb6a27df2b9d6f110c7937"),
]

# Same as above, but using the 0x80 padding byte ("Tiger2").
TIGER192V2_VECTORS = [
    (b"", "4441be75f6018773c206c22745374b924aa8313fef919f41"),
    (b"abc", "f68d7bc5af4b43a06e048d7829560d4a9415658bb0b1f3bf"),
    (b"Tiger", "fe40798b8eb937fd977608930548d6a894c20b04cbef7a42"),
]

# Cross-checked against the reference Whirlpool.c implementation (NESSIE
# submission, bundled with the whirlpool-py311 PyPI package) compiled as a
# Python extension and run directly.
WHIRLPOOL_VECTORS = [
    (
        b"",
        "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a"
        "73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3",
    ),
    (
        b"abc",
        "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4"
        "c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5",
    ),
]


@pytest.mark.parametrize("data,expected", MD4_VECTORS)
def test_md4_vectors(data: bytes, expected: str) -> None:
    assert get_algorithm("md4")().hash(data).hexdigest() == expected


@pytest.mark.parametrize("data,expected", SHA0_VECTORS)
def test_sha0_vectors(data: bytes, expected: str) -> None:
    assert get_algorithm("sha")().hash(data).hexdigest() == expected


@pytest.mark.parametrize("data,expected", TIGER192V1_VECTORS)
def test_tiger192v1_vectors(data: bytes, expected: str) -> None:
    assert get_algorithm("tiger192v1")().hash(data).hexdigest() == expected


@pytest.mark.parametrize("data,expected", TIGER192V2_VECTORS)
def test_tiger192v2_vectors(data: bytes, expected: str) -> None:
    assert get_algorithm("tiger192v2")().hash(data).hexdigest() == expected


@pytest.mark.parametrize("data,expected", WHIRLPOOL_VECTORS)
def test_whirlpool_vectors(data: bytes, expected: str) -> None:
    assert get_algorithm("whirlpool")().hash(data).hexdigest() == expected
