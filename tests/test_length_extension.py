"""Round-trip tests for the hash length extension attack itself.

Modeled on hlextend/hlextend_testscript.py's extension test: for every
algorithm, sweep a range of secret/known-data/append lengths, forge a new
message + signature via hashle.core.extend(), and confirm the forged
signature is exactly what hashing secret + forged_message would produce.
Since the "attacker" never sees the secret, this proves the attack is
correct without leaking it.
"""

from __future__ import annotations

from os import urandom

import pytest

from hashle.algorithms import get_algorithm
from hashle.core import extend

from .conftest import ALL_ALGORITHM_NAMES


@pytest.mark.parametrize("algorithm", ALL_ALGORITHM_NAMES)
def test_length_extension_round_trip(algorithm: str) -> None:
    cls = get_algorithm(algorithm)

    for secret_len in range(0, 130, 25):
        secret = urandom(secret_len)

        for known_len in (0, 1, 55, 63, 64, 65, 127, 128, 200):
            known = b"A" * known_len

            for append_len in (0, 1, 10, 130):
                append = b"C" * append_len

                start_signature = cls().hash(secret + known).hexdigest()

                result = extend(algorithm, start_signature, known, secret_len, append)

                # The oracle: what hashing secret + forged_message actually
                # produces. The attack is correct iff this matches the
                # signature the (secret-blind) attack code computed.
                expected_signature = cls().hash(secret + result.new_message).hexdigest()

                assert result.new_signature == expected_signature, (
                    f"{algorithm}: secret_len={secret_len} known_len={known_len} "
                    f"append_len={append_len}"
                )

                # The forged message must be exactly known_data + glue padding
                # + append_data, and must literally contain the append data
                # the attacker asked for.
                assert result.new_message.startswith(known)
                assert result.new_message.endswith(append) or append_len == 0


def test_extend_rejects_negative_secret_length() -> None:
    sig = get_algorithm("sha256")().hash(b"").hexdigest()
    with pytest.raises(ValueError):
        extend("sha256", sig, b"", -1, b"x")


def test_extend_unknown_algorithm_raises() -> None:
    with pytest.raises(ValueError):
        extend("not-a-real-algorithm", "00" * 32, b"", 8, b"x")
