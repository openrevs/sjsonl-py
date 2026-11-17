"""Known-answer tests: the spec's examples and fixtures produced by sjsonl-go."""

from __future__ import annotations

from pathlib import Path

import pytest

import sjsonl

VECTORS = Path(__file__).parent / "vectors"


def vec(name: str) -> bytes:
    return (VECTORS / name).read_bytes()


SPEC_DOC = b"""\
{"sjsonl":"doc","version":"0.1","key":"Hdt5Ux+sYIXrVy62PJ7TzYSoXgjAjwoG8oOwflbgQag=","sig":"4A3QVt9/DvASKQuXlTolqT5hJVEhOW2PyNg84ucbW5dYQCm6P5ivlB/NvMeaVSYytZK/xwoB5X/DVHpeYjJ4Cw=="}
{"name": "Bob", "age": 30}
null
{"name": "Alice", "age": 42}
{"address": {"street": "Main", "number":12}}
95
"""

SPEC_PATCH = b"""\
{"sjsonl":"patch","version":"0.1","key":"Hdt5Ux+sYIXrVy62PJ7TzYSoXgjAjwoG8oOwflbgQag=","sig":"yROn8+SLvFyMUOZEbBKS6dluwE13bEVAQyTuPg+pmaYG1yv84lEl1zPHYDedgLDA56cQ3FPB7zCvGhZGEKJFBQ==","base":"20728fa9354b71b9b05f34b3e7bf8f812a00984bc3ee9446069aa54a65b2886e","target":"775a21e81092bede93eb474903b3a8a7cf5d557d38676cc1fc4906e4c2cde879","rm":["7a"]}
{"name": "Alice", "age": 50}
"""


def test_spec_document_verifies() -> None:
    info = sjsonl.verify(SPEC_DOC)
    assert info.hash == "20728fa9354b71b9b05f34b3e7bf8f812a00984bc3ee9446069aa54a65b2886e"
    assert info.signer_key_b64 == "Hdt5Ux+sYIXrVy62PJ7TzYSoXgjAjwoG8oOwflbgQag="


def test_spec_patch_applies_and_round_trips() -> None:
    result, info = sjsonl.apply_patch(SPEC_DOC, SPEC_PATCH)
    assert info.hash == "775a21e81092bede93eb474903b3a8a7cf5d557d38676cc1fc4906e4c2cde879"
    assert b'{"name": "Alice", "age": 50}' in result
    assert b'{"name": "Alice", "age": 42}' not in result
    # Diffing back reproduces the spec's patch byte-for-byte.
    assert sjsonl.diff(SPEC_DOC, result) == SPEC_PATCH


def test_go_signed_documents_match() -> None:
    key = sjsonl.load_private_key(vec("test.key"))
    for name in ("base", "target"):
        signed, info = sjsonl.sign(vec(f"{name}.jsonl"), key)
        assert signed == vec(f"{name}.signed.jsonl")
        assert sjsonl.verify(signed) == info


@pytest.mark.parametrize(
    ("patch_file", "signed"), [("patch.jsonl", True), ("patch.unsigned.jsonl", False)]
)
def test_go_patches_match(patch_file: str, signed: bool) -> None:
    base, target = vec("base.signed.jsonl"), vec("target.signed.jsonl")
    assert sjsonl.diff(base, target, signed=signed) == vec(patch_file)

    result, info = sjsonl.apply_patch(base, vec(patch_file))
    if signed:
        assert result == target
        assert info.signer_id is not None
    else:
        assert result == vec("target.unsigned-result.jsonl")
        assert info.signer_key is None
    assert info.hash == sjsonl.verify(target).hash
