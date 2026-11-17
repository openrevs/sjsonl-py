"""Ed25519 key handling and canonical base64."""

from __future__ import annotations

import base64
import binascii
from typing import TypeAlias

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

PUBLIC_KEY_SIZE = 32
SIGNATURE_SIZE = 64
SEED_SIZE = 32

PrivateKeyLike: TypeAlias = Ed25519PrivateKey | bytes
"""A private key, either as a ``cryptography`` key object or a raw 32-byte seed."""


def b64encode(data: bytes) -> str:
    """Encode bytes as standard, padded base64 (RFC 4648 section 4)."""
    return base64.b64encode(data).decode("ascii")


def b64decode_canonical(s: str) -> bytes:
    """Decode standard padded base64, accepting only the canonical encoding.

    Rejects whitespace, missing or extra padding, the URL-safe alphabet, and
    non-zero trailing bits, so every value has exactly one valid encoding.
    """
    try:
        raw = base64.b64decode(s.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as e:
        raise ValueError(f"invalid base64: {e}") from None
    if b64encode(raw) != s:
        raise ValueError("non-canonical base64")
    return raw


def generate_private_key() -> Ed25519PrivateKey:
    """Generate a new random Ed25519 private key."""
    return Ed25519PrivateKey.generate()


def load_private_key(encoded: str | bytes) -> Ed25519PrivateKey:
    """Load a private key from base64 of its 32-byte seed.

    This is the format written by ``sjsonl keygen`` and read from the
    ``SJSONL_PRIVATE_KEY`` environment variable by the Go CLI. Surrounding
    whitespace (such as a trailing newline in a key file) is ignored.
    """
    if isinstance(encoded, bytes):
        encoded = encoded.decode("ascii")
    try:
        seed = b64decode_canonical(encoded.strip())
    except ValueError as e:
        raise ValueError(f"failed to decode private key: {e}") from None
    if len(seed) != SEED_SIZE:
        raise ValueError(
            f"invalid private key size: expected {SEED_SIZE}-byte seed, got {len(seed)} bytes"
        )
    return Ed25519PrivateKey.from_private_bytes(seed)


def dump_private_key(key: PrivateKeyLike) -> str:
    """Encode a private key as base64 of its 32-byte seed (see :func:`load_private_key`)."""
    return b64encode(private_seed(as_private_key(key)))


def as_private_key(key: PrivateKeyLike) -> Ed25519PrivateKey:
    """Coerce a key object or a raw 32-byte seed to an ``Ed25519PrivateKey``."""
    if isinstance(key, Ed25519PrivateKey):
        return key
    if isinstance(key, (bytes, bytearray, memoryview)):
        if len(key) != SEED_SIZE:
            raise ValueError(f"private key seed must be {SEED_SIZE} bytes, got {len(key)}")
        return Ed25519PrivateKey.from_private_bytes(bytes(key))
    raise TypeError(f"expected Ed25519PrivateKey or 32-byte seed, got {type(key).__name__}")


def private_seed(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
