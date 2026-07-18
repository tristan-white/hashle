"""End-to-end tests for the hashle CLI (built with Typer)."""

from __future__ import annotations

import hashlib

from typer.testing import CliRunner

from hashle.cli import app

runner = CliRunner()


def test_list_algorithms_includes_all_supported() -> None:
    result = runner.invoke(app, ["list-algorithms"])
    assert result.exit_code == 0
    for name in ("md4", "md5", "sha1", "sha256", "sha512", "whirlpool", "tiger192v1"):
        assert name in result.stdout


def test_hash_command_matches_hashlib() -> None:
    result = runner.invoke(app, ["hash", "sha256", "--data", "hello world"])
    assert result.exit_code == 0
    assert result.stdout.strip() == hashlib.sha256(b"hello world").hexdigest()


def test_hash_command_hex_input() -> None:
    result = runner.invoke(app, ["hash", "sha256", "--data", "68656c6c6f", "--data-format", "hex"])
    assert result.exit_code == 0
    assert result.stdout.strip() == hashlib.sha256(b"hello").hexdigest()


def test_extend_command_forges_valid_signature() -> None:
    secret = b"secretkey"
    known = b"count=10&user=alice"
    append = b"&admin=true"
    signature = hashlib.sha256(secret + known).hexdigest()

    result = runner.invoke(
        app,
        [
            "extend",
            "--signature", signature,
            "--data", known.decode(),
            "--append", append.decode(),
            "--format", "sha256",
            "--secret-length", str(len(secret)),
            "--out-data-format", "hex",
            "--quiet",
        ],
    )
    assert result.exit_code == 0

    lines = result.stdout.strip().splitlines()
    assert len(lines) == 2
    new_signature, new_data_hex = lines
    new_message = bytes.fromhex(new_data_hex)

    assert hashlib.sha256(secret + new_message).hexdigest() == new_signature
    assert new_message.startswith(known)
    assert new_message.endswith(append)


def test_extend_command_secret_range_produces_multiple_results() -> None:
    secret = b"abcdefgh"
    known = b"data"
    signature = hashlib.sha256(secret + known).hexdigest()

    result = runner.invoke(
        app,
        [
            "extend",
            "--signature", signature,
            "--data", known.decode(),
            "--append", "x",
            "--format", "sha256",
            "--secret-min", "6",
            "--secret-max", "10",
            "--quiet",
        ],
    )
    assert result.exit_code == 0
    # 2 lines of output (signature + data) per secret length tried.
    assert len(result.stdout.strip().splitlines()) == 2 * (10 - 6 + 1)
