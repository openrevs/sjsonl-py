"""Core SJSONL implementation: line sets, signing, diffing and patching."""

from __future__ import annotations

import bisect
import hashlib
import json
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any, NoReturn

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._keys import (
    PUBLIC_KEY_SIZE,
    SIGNATURE_SIZE,
    PrivateKeyLike,
    as_private_key,
    b64decode_canonical,
    b64encode,
    public_bytes,
)
from .errors import (
    BaseMismatchError,
    DocHashFormatError,
    DuplicateLineError,
    EmptyLineError,
    HeaderError,
    InvalidJSONError,
    KeyFormatError,
    MissingSignatureError,
    MultiLineError,
    RmFormatError,
    SignatureFormatError,
    SignatureVerificationError,
    TargetMismatchError,
    UnmatchedPrefixError,
    UnsupportedVersionError,
)

FORMAT_VERSION = "0.1"
"""The SJSONL format version this library reads and writes."""

_HASH_HEX_LEN = 64
_HEX_CHARS = frozenset("0123456789abcdef")
# JSON whitespace only (RFC 8259 section 2). Not bytes.strip()'s default set,
# which also removes VT and FF.
_WHITESPACE = b" \t\n\r"
_SNIPPET_LEN = 60

Data = bytes | str
"""Input accepted wherever a file's contents are expected. ``str`` is UTF-8 encoded."""


# --------------------------------------------------------------------------
# Lines


@dataclass(frozen=True, slots=True)
class Line:
    """A single data line: its exact (whitespace-trimmed) bytes and SHA256 hash."""

    data: bytes
    """The line's bytes, with leading and trailing whitespace removed."""
    hash: str
    """Lowercase hex SHA256 of :attr:`data`."""

    @classmethod
    def from_bytes(cls, raw: bytes, lineno: int | None = None) -> Line:
        """Trim and validate a raw line, then hash it."""
        data = raw.strip(_WHITESPACE)
        if not data:
            raise EmptyLineError("empty JSON line", lineno)
        if b"\r" in data or b"\n" in data:
            raise MultiLineError("JSON must be a single line", lineno)
        _validate_json(data, lineno)
        return cls(data, hashlib.sha256(data).hexdigest())

    @property
    def text(self) -> str:
        """The line decoded as UTF-8."""
        return self.data.decode("utf-8")

    def value(self) -> Any:
        """Parse and return the line's JSON value."""
        return json.loads(self.data)


def _reject_constant(name: str) -> NoReturn:
    raise ValueError(f"{name} is not valid JSON")


def _validate_json(data: bytes, lineno: int | None) -> None:
    try:
        json.loads(data.decode("utf-8"), parse_constant=_reject_constant)
    except UnicodeDecodeError:
        raise InvalidJSONError("line is not valid UTF-8", lineno) from None
    except ValueError as e:
        raise InvalidJSONError(f"not valid JSON: {e}", lineno) from None
    except RecursionError:
        raise InvalidJSONError("JSON nesting too deep", lineno) from None


def _snippet(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    return text if len(text) <= _SNIPPET_LEN else text[:_SNIPPET_LEN] + "..."


def _to_bytes(data: Data) -> bytes:
    if isinstance(data, str):
        return data.encode("utf-8")
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    raise TypeError(f"expected bytes or str, got {type(data).__name__}")


def _split(data: Data) -> list[bytes]:
    """Split JSONL into raw lines, dropping one trailing newline."""
    raw = _to_bytes(data)
    if not raw:
        return []
    lines = raw.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    return lines


def _hash_lines(raw_lines: Sequence[bytes], first_lineno: int) -> tuple[Line, ...]:
    """Validate and hash lines, rejecting duplicates. Returns lines sorted by hash."""
    seen: set[str] = set()
    lines: list[Line] = []
    for i, raw in enumerate(raw_lines):
        lineno = i + first_lineno
        line = Line.from_bytes(raw, lineno)
        if line.hash in seen:
            raise DuplicateLineError(f"duplicate JSON line: {_snippet(line.data)}", lineno)
        seen.add(line.hash)
        lines.append(line)
    lines.sort(key=lambda ln: ln.hash)
    return tuple(lines)


def _signing_message(lines: Sequence[Line]) -> bytes:
    """Concatenate the raw hashes of lines already sorted by hash."""
    return b"".join(bytes.fromhex(ln.hash) for ln in lines)


def _document_hash(lines: Sequence[Line]) -> str:
    return hashlib.sha256(_signing_message(lines)).hexdigest()


def _verify(lines: Sequence[Line], key: bytes, sig: bytes) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, _signing_message(lines))
    except InvalidSignature:
        raise SignatureVerificationError("signature verification failed") from None


def dumps_line(value: Any) -> str:
    """Serialize a value as a compact, stable JSON line.

    SJSONL hashes lines exactly as written and never canonicalizes, so this is
    a convenience, not a requirement. It follows the specification's
    (non-normative) encoding recommendations closely enough that an unchanged
    value encodes to the same bytes every time: no insignificant whitespace,
    keys sorted at every level, UTF-8 output rather than ``\\u`` escapes, and
    NaN/Infinity rejected. Python sorts keys by code point; this matches the
    recommended UTF-16 ordering except for keys mixing astral and high-BMP
    characters.
    """
    return json.dumps(
        value, separators=(",", ":"), sort_keys=True, ensure_ascii=False, allow_nan=False
    )


# --------------------------------------------------------------------------
# Header


@dataclass(frozen=True, slots=True)
class Info:
    """Summary of a document: its hash and, if signed, its signer."""

    hash: str
    """The document hash (lowercase hex SHA256 of the signing message)."""
    signer_key: bytes | None = None
    """The signer's raw 32-byte Ed25519 public key, or ``None`` if unsigned."""
    signer_id: str | None = None
    """Lowercase hex SHA256 of :attr:`signer_key`, or ``None`` if unsigned."""

    @property
    def signer_key_b64(self) -> str | None:
        """The signer's public key as base64, as it appears in a header line."""
        return None if self.signer_key is None else b64encode(self.signer_key)


@dataclass(frozen=True, slots=True)
class _Header:
    kind: str
    key: bytes | None
    sig: bytes | None
    base: str = ""
    target: str = ""
    rm: tuple[str, ...] = ()


def _is_lower_hex(s: str) -> bool:
    return all(c in _HEX_CHARS for c in s)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # Keys arrive already unescaped, so "sjsonl" repeats "sjsonl".
    obj: dict[str, Any] = {}
    for k, v in pairs:
        if k in obj:
            raise HeaderError(f"duplicate key {k!r} in header")
        obj[k] = v
    return obj


def _parse_header(raw: bytes) -> _Header:
    try:
        obj = json.loads(
            raw.strip(_WHITESPACE).decode("utf-8"),
            parse_constant=_reject_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except HeaderError:
        raise
    except (ValueError, RecursionError) as e:
        raise HeaderError(f"header line is not valid JSON: {e}") from None
    if not isinstance(obj, dict):
        raise HeaderError("header line must be a JSON object")

    kind = obj.get("sjsonl")
    if kind not in ("doc", "patch"):
        raise HeaderError(f"unknown sjsonl type {kind!r}")

    version = obj.get("version")
    if version != FORMAT_VERSION:
        raise UnsupportedVersionError(f"unsupported sjsonl version {version!r}")

    # Documents must be signed. Patches may omit key and sig together, but
    # not just one of them.
    key = sig = None
    if kind == "doc" or "key" in obj or "sig" in obj:
        key = _decode_fixed(obj.get("key"), PUBLIC_KEY_SIZE, KeyFormatError, "key")
        sig = _decode_fixed(obj.get("sig"), SIGNATURE_SIZE, SignatureFormatError, "sig")

    if kind == "doc":
        return _Header(kind, key, sig)

    return _Header(
        kind,
        key,
        sig,
        base=_parse_doc_hash(obj, "base"),
        target=_parse_doc_hash(obj, "target"),
        rm=_parse_rm(obj),
    )


def _decode_fixed(value: Any, size: int, error: type[HeaderError], field: str) -> bytes:
    if not isinstance(value, str):
        raise error(f"'{field}' must be a base64 string")
    try:
        raw = b64decode_canonical(value)
    except ValueError as e:
        raise error(f"'{field}': {e}") from None
    if len(raw) != size:
        raise error(f"'{field}' must decode to {size} bytes, got {len(raw)}")
    return raw


def _parse_doc_hash(obj: dict[str, Any], field: str) -> str:
    v = obj.get(field)
    if v is None:
        raise DocHashFormatError(f"missing '{field}'")
    if not isinstance(v, str) or len(v) != _HASH_HEX_LEN or not _is_lower_hex(v):
        raise DocHashFormatError(f"'{field}' must be {_HASH_HEX_LEN} lowercase hex characters")
    return v


def _parse_rm(obj: dict[str, Any]) -> tuple[str, ...]:
    if "rm" not in obj:
        raise RmFormatError("missing 'rm'")
    rm = obj["rm"]
    if not isinstance(rm, list):
        raise RmFormatError("'rm' must be an array")
    for p in rm:
        if not isinstance(p, str) or not _is_lower_hex(p):
            raise RmFormatError(f"'rm' entries must be lowercase hex strings, got {p!r}")
    return tuple(rm)


def _header_json(fields: dict[str, Any]) -> bytes:
    return json.dumps(fields, separators=(",", ":")).encode("ascii")


# --------------------------------------------------------------------------
# Documents


@dataclass(frozen=True, slots=True)
class Document:
    """An SJSONL document: a set of JSON lines, optionally with a signature.

    Lines are held sorted by hash. Construct with :meth:`parse` (a signed
    document, verified), :meth:`from_jsonl` (plain JSONL, unsigned), or
    :meth:`sign`. Instances are immutable.
    """

    lines: tuple[Line, ...]
    key: bytes | None = None
    """Raw 32-byte Ed25519 public key, or ``None`` if unsigned."""
    sig: bytes | None = None
    """Raw 64-byte Ed25519 signature, or ``None`` if unsigned."""

    @classmethod
    def parse(cls, data: Data) -> Document:
        """Parse a signed SJSONL document and verify its signature."""
        raw_lines = _split(data)
        if not raw_lines:
            raise HeaderError("missing header line")
        header = _parse_header(raw_lines[0])
        if header.kind != "doc":
            raise HeaderError(f"expected a signed document, got sjsonl type {header.kind!r}")
        assert header.key is not None
        assert header.sig is not None
        lines = _hash_lines(raw_lines[1:], first_lineno=2)
        _verify(lines, header.key, header.sig)
        return cls(lines, header.key, header.sig)

    @classmethod
    def from_jsonl(cls, data: Data) -> Document:
        """Build an unsigned document from plain JSONL (no header line).

        Empty input yields an empty document.
        """
        return cls(_hash_lines(_split(data), first_lineno=1))

    @classmethod
    def from_lines(cls, lines: Sequence[Data]) -> Document:
        """Build an unsigned document from individual lines (without newlines)."""
        return cls(_hash_lines([_to_bytes(ln) for ln in lines], first_lineno=1))

    def sign(self, private_key: PrivateKeyLike) -> Document:
        """Return a copy of this document signed with ``private_key``.

        ``private_key`` is an ``Ed25519PrivateKey`` or a raw 32-byte seed.
        """
        pk = as_private_key(private_key)
        sig = pk.sign(_signing_message(self.lines))
        return Document(self.lines, public_bytes(pk), sig)

    @property
    def signed(self) -> bool:
        return self.key is not None

    @property
    def hash(self) -> str:
        """The document hash: lowercase hex SHA256 of the signing message."""
        return _document_hash(self.lines)

    @property
    def info(self) -> Info:
        if self.key is None:
            return Info(self.hash)
        return Info(self.hash, self.key, hashlib.sha256(self.key).hexdigest())

    @property
    def line_hashes(self) -> tuple[str, ...]:
        return tuple(ln.hash for ln in self.lines)

    def __len__(self) -> int:
        return len(self.lines)

    def __iter__(self) -> Iterator[Line]:
        return iter(self.lines)

    def __contains__(self, item: object) -> bool:
        """Test membership by :class:`Line` or by line hash."""
        h = item.hash if isinstance(item, Line) else item
        if not isinstance(h, str):
            return False
        hashes = self.line_hashes
        i = bisect.bisect_left(hashes, h)
        return i < len(hashes) and hashes[i] == h

    def header(self) -> bytes | None:
        """The serialized header line (without newline), or ``None`` if unsigned."""
        if self.key is None or self.sig is None:
            return None
        return _header_json(
            {
                "sjsonl": "doc",
                "version": FORMAT_VERSION,
                "key": b64encode(self.key),
                "sig": b64encode(self.sig),
            }
        )

    def to_bytes(self) -> bytes:
        """Serialize: header line (if signed) then data lines sorted by hash.

        An unsigned document serializes as plain JSONL with no header.
        """
        parts = [ln.data for ln in self.lines]
        header = self.header()
        if header is not None:
            parts.insert(0, header)
        return b"".join(p + b"\n" for p in parts)

    def diff(self, target: Document, *, signed: bool = True) -> Patch:
        """Create a patch that turns this document into ``target``.

        With ``signed=True`` (the default) the patch carries ``target``'s key
        and signature, so applying it yields a verified, signed document;
        ``target`` must then be signed. With ``signed=False`` the patch omits
        them, for internal or trusted use.
        """
        if signed and (target.key is None or target.sig is None):
            raise MissingSignatureError("cannot create a signed patch: target is unsigned")

        target_hashes = set(target.line_hashes)
        base_hashes = self.line_hashes
        removed = {h for h in base_hashes if h not in target_hashes}
        added = tuple(ln for ln in target.lines if ln not in self)

        return Patch(
            base=self.hash,
            target=target.hash,
            rm=_unique_prefixes(removed, base_hashes),
            lines=added,
            key=target.key if signed else None,
            sig=target.sig if signed else None,
        )

    def apply(self, patch: Patch) -> Document:
        """Apply ``patch`` to this document and return the verified result.

        Checks the patch's ``base`` and ``target`` hashes and, for a signed
        patch, the result's signature. Applying an unsigned patch yields an
        unsigned document.
        """
        if patch.base != self.hash:
            raise BaseMismatchError(
                f"patch base does not match document: base {patch.base}, document {self.hash}"
            )

        hashes = self.line_hashes
        remove = [False] * len(hashes)
        for prefix in patch.rm:
            lo = bisect.bisect_left(hashes, prefix)
            # Every hex character sorts before "g", so this bounds the prefix range.
            hi = bisect.bisect_left(hashes, prefix + "g", lo)
            if lo == hi:
                raise UnmatchedPrefixError(f"rm prefix {prefix!r} matches no line")
            remove[lo:hi] = [True] * (hi - lo)

        kept = [ln for ln, rm in zip(self.lines, remove, strict=True) if not rm]
        kept_hashes = {ln.hash for ln in kept}
        for ln in patch.lines:
            if ln.hash in kept_hashes:
                raise DuplicateLineError(f"patch adds line already in base: {_snippet(ln.data)}")
        new_lines = tuple(sorted(kept + list(patch.lines), key=lambda ln: ln.hash))

        result_hash = _document_hash(new_lines)
        if result_hash != patch.target:
            raise TargetMismatchError(
                f"patch target does not match patched document: "
                f"target {patch.target}, patched {result_hash}"
            )

        if patch.key is not None and patch.sig is not None:
            _verify(new_lines, patch.key, patch.sig)
        return Document(new_lines, patch.key, patch.sig)


def _common_prefix_len(a: str, b: str) -> int:
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    return n


def _unique_prefixes(targets: set[str], all_sorted: Sequence[str]) -> tuple[str, ...]:
    """Shortest prefix of each target hash that matches no non-target hash.

    The longest common prefix between a target and any non-target is attained
    at its nearest non-target neighbours in sorted order, so two linear scans
    suffice. Output is deduplicated and sorted, matching sjsonl-go.
    """
    if not targets:
        return ()
    need = dict.fromkeys(targets, 0)
    for order in (all_sorted, reversed(all_sorted)):
        last: str | None = None
        for h in order:
            if h in targets:
                if last is not None:
                    need[h] = max(need[h], _common_prefix_len(h, last))
            else:
                last = h
    return tuple(sorted({h[: n + 1] for h, n in need.items()}))


# --------------------------------------------------------------------------
# Patches


@dataclass(frozen=True, slots=True)
class Patch:
    """An SJSONL patch: lines to remove (by hash prefix) and lines to add."""

    base: str
    """Document hash of the document this patch applies to."""
    target: str
    """Document hash of the patched result."""
    rm: tuple[str, ...]
    """Hash prefixes of base lines to remove."""
    lines: tuple[Line, ...]
    """Lines to add."""
    key: bytes | None = None
    """The target document's public key, or ``None`` for an unsigned patch."""
    sig: bytes | None = None
    """The target document's signature, or ``None`` for an unsigned patch."""

    @classmethod
    def parse(cls, data: Data) -> Patch:
        """Parse an SJSONL patch file. The signature is checked when applied."""
        raw_lines = _split(data)
        if not raw_lines:
            raise HeaderError("missing header line")
        header = _parse_header(raw_lines[0])
        if header.kind != "patch":
            raise HeaderError(f"expected a patch, got sjsonl type {header.kind!r}")
        return cls(
            base=header.base,
            target=header.target,
            rm=header.rm,
            lines=_hash_lines(raw_lines[1:], first_lineno=2),
            key=header.key,
            sig=header.sig,
        )

    @property
    def signed(self) -> bool:
        return self.key is not None

    def header(self) -> bytes:
        """The serialized header line, without newline."""
        fields: dict[str, Any] = {"sjsonl": "patch", "version": FORMAT_VERSION}
        if self.key is not None and self.sig is not None:
            fields["key"] = b64encode(self.key)
            fields["sig"] = b64encode(self.sig)
        fields["base"] = self.base
        fields["target"] = self.target
        fields["rm"] = list(self.rm)
        return _header_json(fields)

    def to_bytes(self) -> bytes:
        """Serialize: header line then added lines sorted by hash."""
        return b"".join(p + b"\n" for p in [self.header(), *(ln.data for ln in self.lines)])


# --------------------------------------------------------------------------
# Byte-level convenience API (mirrors sjsonl-go)


def sign(data: Data, private_key: PrivateKeyLike) -> tuple[bytes, Info]:
    """Sign plain JSONL. Returns the signed document and its :class:`Info`."""
    doc = Document.from_jsonl(data).sign(private_key)
    return doc.to_bytes(), doc.info


def verify(data: Data) -> Info:
    """Verify a signed document. Raises :class:`~sjsonl.errors.SJSONLError` if invalid."""
    return Document.parse(data).info


def diff(base: Data, target: Data, *, signed: bool = True) -> bytes:
    """Create a patch between two signed documents.

    With ``signed=False`` the patch omits the target's key and signature.
    """
    return Document.parse(base).diff(Document.parse(target), signed=signed).to_bytes()


def apply_patch(base: Data, patch: Data) -> tuple[bytes, Info]:
    """Apply a patch to a signed document. Returns the result and its :class:`Info`.

    A signed patch yields a verified signed document; an unsigned patch
    yields plain JSONL (no header line) and an :class:`Info` with no signer.
    """
    result = Document.parse(base).apply(Patch.parse(patch))
    return result.to_bytes(), result.info
