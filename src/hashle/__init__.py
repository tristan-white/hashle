"""hashle: a library and CLI for hash length extension attacks."""

from .cli import main
from .core import ExtensionResult, extend, hash_data, list_algorithms

__all__ = ["main", "ExtensionResult", "extend", "hash_data", "list_algorithms"]
