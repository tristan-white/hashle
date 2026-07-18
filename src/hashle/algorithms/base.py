"""Generic resumable Merkle-Damgard hash engine.

Every hash algorithm supported by hash_extender (see
``hash_extender/hash_extender_engine.c``) is a Merkle-Damgard construction:
the message is split into fixed size blocks, a compression function mixes
each block into a running state, and the final block is padded with a
``1`` bit, zero bits, and the bit-length of the original message.

The defining property that makes hash length extension attacks possible is
that the *only* input the compression function needs is the current state
(the digest of everything hashed so far) - it has no memory of anything
that came before that state. This class implements that generic behaviour
once, and each concrete algorithm module only has to provide:

* ``iv()``           - the initial state (as a tuple of unsigned integers)
* ``compress()``     - the compression function for a single block
* ``state_to_bytes`` / ``bytes_to_state`` - how the state is serialized to
  the hexadecimal digest that tools normally deal with.

This mirrors the ``hash_type_t`` struct in
``hash_extender/hash_extender_engine.c``: ``block_size``, ``length_size``,
and ``little_endian`` correspond directly to the fields of that struct.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class HashAlgorithm(ABC):
    """Abstract base class for a resumable Merkle-Damgard hash algorithm."""

    #: Canonical name of the algorithm, used for CLI/library lookups.
    name: str

    #: Size, in bytes, of the final digest.
    digest_size: int

    #: Size, in bytes, of a single compression block.
    block_size: int

    #: Size, in bytes, of the encoded bit-length field appended during
    #: padding (e.g. 8 for MD5/SHA1/SHA256, 16 for SHA512, 32 for Whirlpool).
    length_size: int

    #: Byte order used to encode the bit-length field and the digest words.
    #: ``True`` for little-endian algorithms (MD4, MD5, RIPEMD160, Tiger),
    #: ``False`` for big-endian ones (SHA family, SM3, Whirlpool).
    little_endian: bool

    #: The single byte appended immediately after the message before the
    #: zero padding. Every supported algorithm uses ``0x80`` except
    #: Tiger192v1, which uses ``0x01``.
    pad_byte: int = 0x80

    def __init__(self, state: tuple[int, ...] | None = None, count: int = 0) -> None:
        """Create a hash object, optionally resuming from a known state.

        :param state: internal state words to resume from. When ``None``
            the algorithm's standard initialization vector is used (i.e.
            this behaves like a fresh hash object).
        :param count: number of bytes already logically hashed prior to
            this object's lifetime. Used to compute the correct padding
            length during a length extension attack, where the attacker
            does not see the secret bytes but knows how many there were.
        """
        self.state: tuple[int, ...] = state if state is not None else self.iv()
        self._buffer = b""
        self.count = count

    # -- Algorithm specific hooks -----------------------------------------

    @abstractmethod
    def iv(self) -> tuple[int, ...]:
        """Return the standard initialization vector for this algorithm."""

    @abstractmethod
    def compress(self, state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
        """Mix a single, full-size block into ``state`` and return the new state."""

    @abstractmethod
    def state_to_bytes(self, state: tuple[int, ...]) -> bytes:
        """Serialize a state (or final digest words) to raw bytes."""

    @abstractmethod
    def bytes_to_state(self, data: bytes) -> tuple[int, ...]:
        """Parse raw bytes (e.g. a known signature) back into state words."""

    # -- Generic Merkle-Damgard machinery -----------------------------------

    def update(self, data: bytes) -> "HashAlgorithm":
        """Feed more data into the hash, compressing full blocks as we go."""
        self._buffer += data
        self.count += len(data)
        while len(self._buffer) >= self.block_size:
            block, self._buffer = (
                self._buffer[: self.block_size],
                self._buffer[self.block_size :],
            )
            self.state = self.compress(self.state, block)
        return self

    def padding_for_length(self, total_length: int) -> bytes:
        """Return the pad bytes appended after a message of ``total_length`` bytes.

        This is exactly the padding scheme implemented by
        ``hash_append_data()`` in ``hash_extender/hash_extender_engine.c``:
        a single pad byte, zero bytes, and then the bit-length of the
        message encoded in ``length_size`` bytes, chosen so the padded
        message is a whole number of blocks.
        """
        pad = bytes([self.pad_byte])
        # Pad with zero bytes until exactly `length_size` bytes remain to
        # reach a multiple of block_size.
        remainder = (total_length + len(pad)) % self.block_size
        zeros_needed = (self.block_size - self.length_size - remainder) % self.block_size
        pad += b"\x00" * zeros_needed

        bit_length = total_length * 8
        length_bytes = bit_length.to_bytes(self.length_size, "little" if self.little_endian else "big")
        pad += length_bytes
        return pad

    def digest(self) -> bytes:
        """Finalize a *copy* of this hash object and return the raw digest."""
        clone = self._clone()
        clone.update(clone.padding_for_length(clone.count))
        # Anything still buffered after padding must be a whole number of
        # blocks (guaranteed by padding_for_length); flush it explicitly in
        # case update() left an empty-but-not-yet-compressed remainder.
        while len(clone._buffer) >= clone.block_size:
            block, clone._buffer = clone._buffer[: clone.block_size], clone._buffer[clone.block_size :]
            clone.state = clone.compress(clone.state, block)
        return clone.state_to_bytes(clone.state)

    def hexdigest(self) -> str:
        return self.digest().hex()

    def _clone(self) -> "HashAlgorithm":
        clone = self.__class__(state=self.state, count=self.count)
        clone._buffer = self._buffer
        return clone

    # -- Convenience helpers used by hashle.core ---------------------------

    def hash(self, message: bytes) -> "HashAlgorithm":
        """Hash ``message`` from scratch (like calling update() on a fresh object)."""
        self.state = self.iv()
        self.count = 0
        self._buffer = b""
        self.update(message)
        return self

    @classmethod
    def from_hexdigest(cls, hexdigest: str, count: int) -> "HashAlgorithm":
        """Build an instance whose state resumes from a previously known digest."""
        instance = cls()
        raw = bytes.fromhex(hexdigest)
        if len(raw) != instance.digest_size:
            raise ValueError(
                f"{instance.name}: expected a {instance.digest_size}-byte "
                f"({instance.digest_size * 2}-hex-char) signature, got {len(raw)} bytes"
            )
        instance.state = instance.bytes_to_state(raw)
        instance.count = count
        return instance
