"""Command line interface for hashle, built with Typer.

The ``extend`` command intentionally mirrors the option names used by the
``hash_extender`` C tool (``--data``/``--file``, ``--signature``,
``--format``, ``--append``/``--appendfile``, ``--secret-length`` /
``--secret-min``/``--secret-max``) so that existing hash_extender
workflows and muscle memory transfer directly.
"""

from __future__ import annotations

from pathlib import Path

import typer

from .algorithms import ALGORITHMS
from .core import ExtensionResult, extend as extend_attack, hash_data

app = typer.Typer(
    name="hashle",
    help="Perform hash length extension attacks against vulnerable Merkle-Damgard hashes.",
    no_args_is_help=True,
    add_completion=False,
)


def _decode(data: str, fmt: str) -> bytes:
    if fmt == "raw":
        return data.encode()
    if fmt == "hex":
        return bytes.fromhex(data)
    raise typer.BadParameter(f"Unsupported format {fmt!r}, expected 'raw' or 'hex'")


def _encode(data: bytes, fmt: str) -> str:
    if fmt == "raw":
        try:
            return data.decode()
        except UnicodeDecodeError:
            return data.decode(errors="backslashreplace")
    if fmt == "hex":
        return data.hex()
    raise typer.BadParameter(f"Unsupported format {fmt!r}, expected 'raw' or 'hex'")


def _read_input(
    value: str | None, file: Path | None, fmt: str, option_name: str
) -> bytes:
    if value is not None and file is not None:
        raise typer.BadParameter(f"Specify only one of --{option_name} or --{option_name}-file")
    if file is not None:
        return file.read_bytes()
    if value is not None:
        return _decode(value, fmt)
    raise typer.BadParameter(f"One of --{option_name} or --{option_name}-file is required")


@app.command("list-algorithms")
def list_algorithms() -> None:
    """List every hash algorithm hashle supports."""
    for name in sorted(ALGORITHMS):
        cls = ALGORITHMS[name]
        typer.echo(f"{name:<12} digest={cls.digest_size * 8} bits  block={cls.block_size} bytes")


@app.command("hash")
def hash_command(
    algorithm: str = typer.Argument(..., help="Hash algorithm to use, see 'list-algorithms'."),
    data: str | None = typer.Option(None, "--data", "-d", help="Data to hash."),
    file: Path | None = typer.Option(None, "--file", help="Read data to hash from a file."),
    data_format: str = typer.Option("raw", "--data-format", help="'raw' or 'hex'."),
) -> None:
    """Compute the digest of DATA, mainly useful for generating test signatures."""
    payload = _read_input(data, file, data_format, "data")
    typer.echo(hash_data(algorithm, payload))


@app.command("extend")
def extend_command(
    signature: str = typer.Option(..., "--signature", "-s", help="Known signature of secret+data, in hex."),
    data: str | None = typer.Option(None, "--data", "-d", help="The original known string."),
    file: Path | None = typer.Option(None, "--file", help="Read the original known string from a file."),
    data_format: str = typer.Option("raw", "--data-format", help="Format of --data: 'raw' or 'hex'."),
    append: str | None = typer.Option(None, "--append", "-a", help="Data to append."),
    append_file: Path | None = typer.Option(None, "--append-file", help="Read data to append from a file."),
    append_format: str = typer.Option("raw", "--append-format", help="Format of --append: 'raw' or 'hex'."),
    format: list[str] = typer.Option(
        ...,
        "--format",
        "-f",
        help="Hash algorithm(s) to target. Repeat for multiple, or pass 'all'.",
    ),
    secret_length: int | None = typer.Option(
        None, "--secret-length", "-l", help="Assumed length of the secret, in bytes."
    ),
    secret_min: int | None = typer.Option(None, "--secret-min", help="Minimum secret length to try."),
    secret_max: int | None = typer.Option(None, "--secret-max", help="Maximum secret length to try."),
    out_data_format: str = typer.Option("raw", "--out-data-format", help="Format for the forged message output."),
    out_signature_format: str = typer.Option("hex", "--out-signature-format", help="Format for the new signature output."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only print the new signature and data."),
) -> None:
    """Perform a hash length extension attack.

    Computes the message an attacker would send, and the signature it
    produces, for every combination of requested hash algorithm(s) and
    secret length(s).
    """
    known_data = _read_input(data, file, data_format, "data")
    append_data = _read_input(append, append_file, append_format, "append")

    if secret_length is not None and (secret_min is not None or secret_max is not None):
        raise typer.BadParameter("--secret-length cannot be combined with --secret-min/--secret-max")
    if secret_length is not None:
        lengths = [secret_length]
    elif secret_min is not None and secret_max is not None:
        if secret_min > secret_max:
            raise typer.BadParameter("--secret-min must be <= --secret-max")
        lengths = list(range(secret_min, secret_max + 1))
    elif secret_min is not None or secret_max is not None:
        raise typer.BadParameter("--secret-min and --secret-max must be given together")
    else:
        lengths = [8]  # hash_extender's own default

    if len(format) == 1 and format[0] == "all":
        algorithms = sorted(
            name for name, cls in ALGORITHMS.items() if cls.digest_size * 2 == len(signature)
        )
        if not algorithms:
            raise typer.BadParameter(f"No known algorithm produces a {len(signature)}-hex-char signature")
    else:
        algorithms = format

    for secret_len in lengths:
        for algorithm in algorithms:
            result: ExtensionResult = extend_attack(algorithm, signature, known_data, secret_len, append_data)

            new_data_out = _encode(result.new_message, out_data_format)
            new_signature_out = _encode(bytes.fromhex(result.new_signature), out_signature_format)

            if quiet:
                typer.echo(new_signature_out)
                typer.echo(new_data_out)
            else:
                typer.echo(f"Type: {algorithm}")
                typer.echo(f"Secret length: {secret_len}")
                typer.echo(f"New signature: {new_signature_out}")
                typer.echo(f"New string: {new_data_out}")
                typer.echo("")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
