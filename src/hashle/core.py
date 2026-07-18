"""High level hash length extension attack API.

This is the library-facing counterpart to hash_extender's
``hash_append_data()`` / ``hash_gen_signature_evil()`` (see
``hash_extender/hash_extender_engine.c``): given a known signature over
``secret || known_data``, an assumed secret length, and data to append,
compute the new message an attacker would send and the signature it
produces -- all without ever knowing the secret itself.
"""

from __future__ import annotations

from dataclasses import dataclass

from .algorithms import ALGORITHMS, get_algorithm


@dataclass(frozen=True)
class ExtensionResult:
    """The result of a hash length extension attack."""

    #: The bytes an attacker would send as the new message, i.e.
    #: ``known_data + glue_padding + append_data``. The secret itself is
    #: never included, since the attacker doesn't know it.
    new_message: bytes

    #: The valid signature for ``secret + new_message``.
    new_signature: str


def list_algorithms() -> list[str]:
    """Return the canonical names of every supported hash algorithm."""
    return sorted(ALGORITHMS)


def hash_data(algorithm: str, data: bytes) -> str:
    """Compute the hex digest of ``data`` using ``algorithm``.

    Mainly useful for generating test signatures and for verifying
    hashle's own algorithm implementations against known data.
    """
    return get_algorithm(algorithm)().hash(data).hexdigest()


def extend(
    algorithm: str,
    signature: str,
    known_data: bytes,
    secret_length: int,
    append_data: bytes,
) -> ExtensionResult:
    """Perform a hash length extension attack.

    :param algorithm: canonical algorithm name, e.g. ``"sha256"``.
    :param signature: the known hex digest of ``secret + known_data``.
    :param known_data: the portion of the original message that is known.
    :param secret_length: assumed length, in bytes, of the unknown secret
        prefix. If this guess is wrong the resulting signature will not
        validate -- callers typically brute force this value.
    :param append_data: the attacker-controlled data to append.
    :return: the forged message (excluding the secret) and its signature.
    """
    if secret_length < 0:
        raise ValueError("secret_length must not be negative")

    cls = get_algorithm(algorithm)

    # The glue padding is whatever padding would have been appended to
    # terminate the *original* message (secret + known_data). The attacker
    # can compute this without knowing the secret's bytes, only its length.
    original_length = secret_length + len(known_data)
    glue = cls().padding_for_length(original_length)

    new_message = known_data + glue + append_data

    # Resume hashing from the known state, pretending we've already
    # processed `original_length + len(glue)` bytes (a whole number of
    # blocks), then hash the appended data and finalize normally.
    resumed = cls.from_hexdigest(signature, count=original_length + len(glue))
    resumed.update(append_data)
    new_signature = resumed.hexdigest()

    return ExtensionResult(new_message=new_message, new_signature=new_signature)
