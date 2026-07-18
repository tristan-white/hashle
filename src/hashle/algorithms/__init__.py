"""Registry of all hash algorithms supported by hashle.

This mirrors the ``hash_type_list`` / ``hash_type_array`` defined in
``hash_extender/hash_extender_engine.c`` -- every hash type that
``hash_extender`` supports (md4, md5, ripemd160, sha, sha1, sha256,
sha512, sm3, tiger192v1, tiger192v2, whirlpool) is implemented here.
"""

from __future__ import annotations

from .base import HashAlgorithm
from .md4 import MD4
from .md5 import MD5
from .ripemd160 import RIPEMD160
from .sha1 import SHA0, SHA1
from .sha256 import SHA256
from .sha512 import SHA512
from .sm3 import SM3
from .tiger import Tiger192v1, Tiger192v2
from .whirlpool import Whirlpool

ALGORITHMS: dict[str, type[HashAlgorithm]] = {
    cls.name: cls
    for cls in (
        MD4,
        MD5,
        RIPEMD160,
        SHA0,
        SHA1,
        SHA256,
        SHA512,
        SM3,
        Tiger192v1,
        Tiger192v2,
        Whirlpool,
    )
}


def get_algorithm(name: str) -> type[HashAlgorithm]:
    """Look up an algorithm class by its canonical name (e.g. ``"sha256"``)."""
    try:
        return ALGORITHMS[name]
    except KeyError as exc:
        available = ", ".join(sorted(ALGORITHMS))
        raise ValueError(f"Unsupported hash algorithm {name!r}. Available: {available}") from exc


__all__ = ["HashAlgorithm", "ALGORITHMS", "get_algorithm"]
