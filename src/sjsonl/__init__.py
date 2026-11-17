"""Signed JSONL (SJSONL): sign, verify, diff and patch JSON Lines documents.

See https://openrevs.org/specs/sjsonl/ for the format specification.

Byte-level API, mirroring sjsonl-go::

    signed, info = sjsonl.sign(data, private_key)
    info = sjsonl.verify(signed)
    patch = sjsonl.diff(base, target)            # or signed=False
    result, info = sjsonl.apply_patch(base, patch)

Object API::

    doc = sjsonl.Document.from_jsonl(data).sign(private_key)
    doc = sjsonl.Document.parse(signed)          # verifies
    patch = base_doc.diff(target_doc)
    result = base_doc.apply(patch)
"""

from importlib.metadata import PackageNotFoundError, version

from . import errors
from ._core import (
    FORMAT_VERSION,
    Document,
    Info,
    Line,
    Patch,
    apply_patch,
    diff,
    dumps_line,
    sign,
    verify,
)
from ._keys import PrivateKeyLike, dump_private_key, generate_private_key, load_private_key
from .errors import SJSONLError

try:
    __version__ = version("sjsonl")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0"

__all__ = [
    "FORMAT_VERSION",
    "Document",
    "Info",
    "Line",
    "Patch",
    "PrivateKeyLike",
    "SJSONLError",
    "__version__",
    "apply_patch",
    "diff",
    "dump_private_key",
    "dumps_line",
    "errors",
    "generate_private_key",
    "load_private_key",
    "sign",
    "verify",
]
