# hashle

`hashle` is a Python library and CLI for performing **hash length extension (HLE) attacks** against vulnerable Merkle-Damgard hash constructions.

Given `H(secret || known_data)`, an assumed length for `secret`, and attacker controlled data, `hashle` computes a new message and a valid signature for `H(secret || known_data || glue_padding || append_data)` -- all *without ever knowing `secret`*.

## Credit

Inspired by the C tool [hash_extender](https://github.com/iagox86/hash_extender) and [hlextend](https://github.com/stephenbradshaw/hlextend).

## Supported algorithms

Every hash algorithm supported by `hash_extender`'s C engine is implemented in
pure Python:

| Algorithm    | Digest size | Block size | Notes                          |
|--------------|-------------|------------|---------------------------------|
| `md4`        | 128 bits    | 64 bytes   |                                  |
| `md5`        | 128 bits    | 64 bytes   |                                  |
| `ripemd160`  | 160 bits    | 64 bytes   |                                  |
| `sha`        | 160 bits    | 64 bytes   | Original 1993 SHA-0             |
| `sha1`       | 160 bits    | 64 bytes   |                                  |
| `sha256`     | 256 bits    | 64 bytes   |                                  |
| `sha512`     | 512 bits    | 128 bytes  |                                  |
| `sm3`        | 256 bits    | 64 bytes   |                                  |
| `tiger192v1` | 192 bits    | 64 bytes   | Uses `0x01` padding byte         |
| `tiger192v2` | 192 bits    | 64 bytes   | "Tiger2", uses `0x80` padding    |
| `whirlpool`  | 512 bits    | 64 bytes   |                                  |

All algorithms are implemented on top of a single generic, resumable Merkle-Damgard engine (`hashle.algorithms.base.HashAlgorithm`) that mirrors [hash_extender_engine.c](https://github.com/iagox86/hash_extender/blob/master/hash_extender_engine.c)'s padding and state-resumption logic, so adding a new algorithm only requires implementing its compression function.

## Installation / development

This project uses [`uv`](https://docs.astral.sh/uv/) for dependency
management. Always prefix Python invocations with `uv run`:

```sh
uv sync
uv run hashle --help
uv run pytest
```

## CLI usage

### List supported algorithms

```sh
uv run hashle list-algorithms
```

### Compute a hash (useful for generating test signatures)

```sh
uv run hashle hash sha256 --data "hello world"
```

### Perform a length extension attack

```sh
uv run hashle extend \
  --signature a2b636472dbba4e53a5e13f1f92f24a9f5d1794d911e7727f268ed8b470b0bfc \
  --data "count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo" \
  --append "&waffle=liege" \
  --format sha256 \
  --secret-length 9
```

Output:

```
Type: sha256
Secret length: 9
New signature: 2e3a006cf5447ef611bdf0cebeb061e676f53dbfeb162aa57233a5bf273a327c
New string: count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo\x80                                                              &waffle=liege
```

Key options (mirroring `hash_extender`'s CLI):

- `--data` / `--file`, `--data-format` (`raw`|`hex`) -- the known message.
- `--signature` -- the known hex digest of `secret + data`.
- `--append` / `--append-file`, `--append-format` -- attacker-controlled data to append.
- `--format` / `-f` -- one or more algorithm names to target, or `all` to try
  every algorithm whose digest length matches `--signature`.
- `--secret-length` -- assumed secret length, or `--secret-min`/`--secret-max`
  to brute force a range of lengths.
- `--out-data-format` / `--out-signature-format` (`raw`|`hex`) -- output encoding.
- `--quiet` -- print only the new signature and new data (one pair of lines
  per secret length / algorithm combination), for easy scripting.

## Library usage

```python
from hashle import extend, hash_data

signature = hash_data("sha256", b"secretkey" + b"count=10")
result = extend(
    algorithm="sha256",
    signature=signature,
    known_data=b"count=10",
    secret_length=len(b"secretkey"),
    append_data=b"&admin=true",
)
print(result.new_message)    # forged message (excludes the secret)
print(result.new_signature)  # valid signature for secret + new_message
```

## Testing

```sh
uv run pytest
```

The test suite (`tests/`):

- `test_hashlib_parity.py` -- cross-checks every hashlib-backed algorithm
  against `hashlib` for message lengths 0-255 and several reference strings.
- `test_known_vectors.py` -- checks the algorithms hashlib doesn't provide
  (md4, sha0, tiger192v1/v2, whirlpool) against published/reference-compiled
  test vectors.
- `test_length_extension.py` -- round-trip tests of the actual attack across
  every algorithm and a sweep of secret/known/append lengths, modeled on
  `hlextend/hlextend_testscript.py`.
- `test_cli.py` -- end-to-end tests of the Typer CLI.
