"""Exceptions raised by sjsonl.

Every exception derives from :class:`SJSONLError`, which is itself a
:class:`ValueError`, so callers can catch everything with one ``except``.
"""

from __future__ import annotations


class SJSONLError(ValueError):
    """Base class for all SJSONL errors."""


class LineError(SJSONLError):
    """A problem with a specific line of input.

    ``lineno`` is the 1-based line number in the original file (counting the
    header line, if any), or ``None`` when the line has no position, such as a
    line added by a patch that collides with the base document.
    """

    def __init__(self, message: str, lineno: int | None = None) -> None:
        self.lineno = lineno
        if lineno is not None:
            message = f"line {lineno}: {message}"
        super().__init__(message)


class EmptyLineError(LineError):
    """A line is empty or contains only whitespace."""


class InvalidJSONError(LineError):
    """A line is not valid JSON (or not valid UTF-8)."""


class MultiLineError(LineError):
    """A line contains an embedded carriage return or newline."""


class DuplicateLineError(LineError):
    """The same line appears more than once in a line set."""


class HeaderError(SJSONLError):
    """The header line is missing or malformed."""


class UnsupportedVersionError(HeaderError):
    """The header names an SJSONL version this library does not support."""


class KeyFormatError(HeaderError):
    """The ``key`` field is missing or not a canonical base64 Ed25519 public key."""


class SignatureFormatError(HeaderError):
    """The ``sig`` field is missing or not a canonical base64 Ed25519 signature."""


class DocHashFormatError(HeaderError):
    """A ``base`` or ``target`` field is missing or not a lowercase hex SHA256."""


class RmFormatError(HeaderError):
    """The ``rm`` field is missing or not an array of lowercase hex strings."""


class MissingSignatureError(SJSONLError):
    """A signature is required but the document or patch has none."""


class SignatureVerificationError(SJSONLError):
    """The Ed25519 signature does not match the line set."""


class PatchError(SJSONLError):
    """A patch cannot be applied to the given base document."""


class BaseMismatchError(PatchError):
    """The patch's ``base`` hash does not match the base document."""


class TargetMismatchError(PatchError):
    """The patched result does not match the patch's ``target`` hash."""


class UnmatchedPrefixError(PatchError):
    """An ``rm`` prefix matches no line of the base document."""
