from __future__ import annotations

import base64
import json
import random

import pytest

import sjsonl
from sjsonl import Document, Patch, errors
from sjsonl._core import _unique_prefixes

SEED = bytes(range(32))
OTHER_SEED = bytes(range(1, 33))

FAKE_KEY = base64.b64encode(b"k" * 32).decode()
FAKE_SIG = base64.b64encode(b"s" * 64).decode()
FAKE_HASH = "ba" * 32


def header(**fields: object) -> bytes:
    return json.dumps({"sjsonl": "doc", "version": "0.1", **fields}).encode()


def signed(data: str, seed: bytes = SEED) -> bytes:
    return sjsonl.sign(data, seed)[0]


# --------------------------------------------------------------------------
# Line validation


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b'{"key": "value"}', b'{"key": "value"}'),
        (b'  {"key": "value"}  ', b'{"key": "value"}'),
        (b'\t {"key": "value"}\r', b'{"key": "value"}'),
        (b'{"message": "line1\\nline2"}', b'{"message": "line1\\nline2"}'),
        (b"null", b"null"),
        (b"95", b"95"),
        ('"héllo"'.encode(), '"héllo"'.encode()),
    ],
)
def test_valid_lines(raw: bytes, expected: bytes) -> None:
    doc = Document.from_lines([raw])
    assert doc.lines[0].data == expected


@pytest.mark.parametrize(
    ("raw", "error"),
    [
        (b"", errors.EmptyLineError),
        (b"   ", errors.EmptyLineError),
        (b'{key: "value"}', errors.InvalidJSONError),
        (b'{"key": "value"', errors.InvalidJSONError),
        (b'x{"key": "value"}', errors.InvalidJSONError),
        (b"NaN", errors.InvalidJSONError),
        (b'{"a": Infinity}', errors.InvalidJSONError),
        (b'"\xff"', errors.InvalidJSONError),
        (b'{\r"key": "value"}', errors.MultiLineError),
        # Only JSON whitespace (space, tab, CR, LF) is trimmed.
        (b"1\x0b", errors.InvalidJSONError),
        (b"\x0c1", errors.InvalidJSONError),
        (b"1\xc2\xa0", errors.InvalidJSONError),
        (b"1\xc2\x85", errors.InvalidJSONError),
        (b"\xe2\x80\xa81", errors.InvalidJSONError),
    ],
)
def test_invalid_lines(raw: bytes, error: type[Exception]) -> None:
    with pytest.raises(error):
        Document.from_lines([raw])


def test_line_errors_report_file_line_numbers() -> None:
    with pytest.raises(errors.InvalidJSONError) as exc:
        Document.from_jsonl("1\n2\nbad\n")
    assert exc.value.lineno == 3

    doc = signed("1\n2\n")
    with pytest.raises(errors.InvalidJSONError) as exc:
        Document.parse(doc + b"bad\n")
    assert exc.value.lineno == 4  # header is line 1


def test_duplicate_lines_rejected_after_trimming() -> None:
    with pytest.raises(errors.DuplicateLineError, match="line 2: duplicate"):
        Document.from_jsonl('{"a": 1}\n  {"a": 1}  \n')


def test_differently_encoded_values_are_distinct_lines() -> None:
    doc = Document.from_jsonl('{"a":1}\n{"a": 1}\n')
    assert len(doc) == 2


def test_trailing_newline_optional_but_only_one() -> None:
    assert Document.from_jsonl("1\n2").hash == Document.from_jsonl("1\n2\n").hash
    with pytest.raises(errors.EmptyLineError):
        Document.from_jsonl("1\n2\n\n")


# --------------------------------------------------------------------------
# Signing and verification


def test_sign_verify_round_trip() -> None:
    out, info = sjsonl.sign('{"b": 2}\n{"a": 1}\n', SEED)
    assert sjsonl.verify(out) == info
    assert info.signer_key is not None
    assert info.signer_id is not None and len(info.signer_id) == 64


def test_line_order_does_not_matter() -> None:
    a, _ = sjsonl.sign("1\n2\n3\n", SEED)
    b, _ = sjsonl.sign("3\n1\n2\n", SEED)
    assert a == b
    # Reordering lines of a signed document keeps it valid.
    hdr, *lines = a.splitlines()
    assert sjsonl.verify(b"\n".join([hdr, *reversed(lines)]))


def test_empty_document_is_signable() -> None:
    out, info = sjsonl.sign("", SEED)
    assert out.count(b"\n") == 1
    assert sjsonl.verify(out) == info
    assert info.hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_accepts_str_and_key_object() -> None:
    key = sjsonl.load_private_key(base64.b64encode(SEED).decode())
    assert sjsonl.sign("1\n", key) == sjsonl.sign(b"1\n", SEED)


def test_tampered_line_fails_verification() -> None:
    doc = signed('{"a": 1}\n{"b": 2}\n')
    with pytest.raises(errors.SignatureVerificationError):
        sjsonl.verify(doc.replace(b'"b": 2', b'"b": 3'))


def test_added_or_removed_line_fails_verification() -> None:
    doc = signed("1\n2\n")
    with pytest.raises(errors.SignatureVerificationError):
        sjsonl.verify(doc + b"3\n")
    with pytest.raises(errors.SignatureVerificationError):
        sjsonl.verify(doc.splitlines()[0] + b"\n1\n")


def test_wrong_key_fails_verification() -> None:
    mine = Document.parse(signed("1\n"))
    other = Document.parse(signed("1\n", OTHER_SEED))
    swapped = Document(mine.lines, other.key, mine.sig)
    with pytest.raises(errors.SignatureVerificationError):
        sjsonl.verify(swapped.to_bytes())


def test_verify_requires_header() -> None:
    with pytest.raises(errors.HeaderError):
        sjsonl.verify(b"")
    with pytest.raises(errors.HeaderError):
        sjsonl.verify(b'{"a": 1}\n')


def test_verify_rejects_patch() -> None:
    patch = sjsonl.diff(signed("1\n"), signed("2\n"))
    with pytest.raises(errors.HeaderError, match="expected a signed document"):
        sjsonl.verify(patch)


# --------------------------------------------------------------------------
# Header parsing


B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def setbits(b64: str) -> str:
    """Set a (normally zero) trailing bit of a padded base64 value."""
    data = b64.rstrip("=")
    last = B64_ALPHABET[B64_ALPHABET.index(data[-1]) ^ 1]
    return data[:-1] + last + b64[len(data) :]


@pytest.mark.parametrize(
    ("hdr", "error"),
    [
        (b'{"sjsonl": "doc", "version": "0.1"}', errors.KeyFormatError),
        (header(key=FAKE_KEY), errors.SignatureFormatError),
        (header(key="invalid@b64!", sig=FAKE_SIG), errors.KeyFormatError),
        (header(key=FAKE_KEY, sig="invalid@b64!"), errors.SignatureFormatError),
        (header(key="6b" * 32, sig=FAKE_SIG), errors.KeyFormatError),
        (header(key=setbits(FAKE_KEY), sig=FAKE_SIG), errors.KeyFormatError),
        (header(key=FAKE_KEY, sig=setbits(FAKE_SIG)), errors.SignatureFormatError),
        (header(key=FAKE_KEY.rstrip("="), sig=FAKE_SIG), errors.KeyFormatError),
        (header(key=FAKE_KEY, sig=FAKE_SIG.rstrip("=")), errors.SignatureFormatError),
        (
            header(key=base64.urlsafe_b64encode(b"\xfb" * 32).decode(), sig=FAKE_SIG),
            errors.KeyFormatError,
        ),
        (header(key=FAKE_KEY[:20] + "\n" + FAKE_KEY[20:], sig=FAKE_SIG), errors.KeyFormatError),
        (header(key="abcd", sig=FAKE_SIG), errors.KeyFormatError),
        (header(key=FAKE_KEY, sig="abcd"), errors.SignatureFormatError),
        (header(key=123, sig=FAKE_SIG), errors.KeyFormatError),
        (b'{"sjsonl": "doc", "version": "9", "key": "x"}', errors.UnsupportedVersionError),
        (b'{"sjsonl": "doc"}', errors.UnsupportedVersionError),
        (b'{"sjsonl": "nope", "version": "0.1"}', errors.HeaderError),
        (b"[1, 2]", errors.HeaderError),
        (b"not json", errors.HeaderError),
    ],
)
def test_bad_doc_headers(hdr: bytes, error: type[Exception]) -> None:
    with pytest.raises(error):
        sjsonl.verify(hdr + b"\n")


def test_well_formed_fake_header_parses_but_fails_verification() -> None:
    with pytest.raises(errors.SignatureVerificationError):
        sjsonl.verify(header(key=FAKE_KEY, sig=FAKE_SIG) + b"\n")


@pytest.mark.parametrize("dup", [b',"sjsonl":"patch"', b',"\\u0073jsonl":"doc"', b',"sig":"x"'])
def test_duplicate_header_keys_rejected(dup: bytes) -> None:
    # Without the check these would parse (last value wins) and fail later,
    # or not at all, depending on which value the parser kept.
    hdr = header(key=FAKE_KEY, sig=FAKE_SIG)
    with pytest.raises(errors.HeaderError, match="duplicate key"):
        sjsonl.verify(hdr[:-1] + dup + b"}\n")


@pytest.mark.parametrize("ws", [b"\x0b", b"\x0c", b"\xc2\xa0", b"\xe2\x80\xa8"])
def test_header_non_json_whitespace_rejected(ws: bytes) -> None:
    hdr = header(key=FAKE_KEY, sig=FAKE_SIG)
    with pytest.raises(errors.HeaderError, match="not valid JSON"):
        sjsonl.verify(hdr + ws + b"\n")


def test_header_crlf_accepted() -> None:
    doc = signed("1\n2\n")
    assert sjsonl.verify(doc.replace(b"\n", b"\r\n"))


def patch_header(**fields: object) -> bytes:
    base: dict[str, object] = {
        "sjsonl": "patch",
        "version": "0.1",
        "base": FAKE_HASH,
        "target": FAKE_HASH,
        "rm": [],
    }
    base.update(fields)
    return json.dumps({k: v for k, v in base.items() if v is not None}).encode()


@pytest.mark.parametrize(
    ("hdr", "error"),
    [
        (patch_header(base=None), errors.DocHashFormatError),
        (patch_header(target=None), errors.DocHashFormatError),
        (patch_header(base="BA" * 32), errors.DocHashFormatError),
        (patch_header(base="ba" * 16), errors.DocHashFormatError),
        (patch_header(target=12), errors.DocHashFormatError),
        (patch_header(rm=None), errors.RmFormatError),
        (patch_header(rm="7a"), errors.RmFormatError),
        (patch_header(rm=["7A"]), errors.RmFormatError),
        (patch_header(rm=["xyz"]), errors.RmFormatError),
        (patch_header(rm=[7]), errors.RmFormatError),
        (patch_header(key=FAKE_KEY), errors.SignatureFormatError),
        (patch_header(sig=FAKE_SIG), errors.KeyFormatError),
    ],
)
def test_bad_patch_headers(hdr: bytes, error: type[Exception]) -> None:
    with pytest.raises(error):
        Patch.parse(hdr + b"\n")


def test_unsigned_patch_header_parses() -> None:
    p = Patch.parse(patch_header(rm=["", "7a"]) + b"\n1\n")
    assert not p.signed
    assert p.rm == ("", "7a")
    assert len(p.lines) == 1


# --------------------------------------------------------------------------
# Diff and patch


def test_diff_and_patch_round_trip() -> None:
    base = signed('{"a": 1}\n{"b": 2}\n{"c": 3}\n')
    target = signed('{"a": 1}\n{"b": 20}\n{"d": 4}\n')
    patch = sjsonl.diff(base, target)
    p = Patch.parse(patch)
    assert sorted(ln.data for ln in p.lines) == [b'{"b": 20}', b'{"d": 4}']
    assert len(p.rm) == 2

    result, info = sjsonl.apply_patch(base, patch)
    assert result == target
    assert info == sjsonl.verify(target)


def test_identical_documents_give_empty_patch() -> None:
    doc = signed("1\n2\n")
    p = Patch.parse(sjsonl.diff(doc, doc))
    assert p.rm == () and p.lines == ()
    assert sjsonl.apply_patch(doc, sjsonl.diff(doc, doc))[0] == doc


def test_full_replacement_with_empty_prefix() -> None:
    base = Document.parse(signed("1\n2\n"))
    target = Document.parse(signed("3\n"))
    p = Patch(base.hash, target.hash, ("",), target.lines, target.key, target.sig)
    assert base.apply(p) == target


def test_patch_to_and_from_empty_document() -> None:
    empty, full = signed(""), signed("1\n2\n")
    assert sjsonl.apply_patch(empty, sjsonl.diff(empty, full))[0] == full
    assert sjsonl.apply_patch(full, sjsonl.diff(full, empty))[0] == empty


def test_patch_base_mismatch() -> None:
    patch = sjsonl.diff(signed("1\n"), signed("2\n"))
    with pytest.raises(errors.BaseMismatchError):
        sjsonl.apply_patch(signed("3\n"), patch)


def test_patch_target_mismatch() -> None:
    base, target = signed("1\n"), signed("2\n")
    p = Patch.parse(sjsonl.diff(base, target))
    bad = Patch(p.base, "00" * 32, p.rm, p.lines, p.key, p.sig)
    with pytest.raises(errors.TargetMismatchError):
        Document.parse(base).apply(bad)


def test_patch_with_wrong_signature_fails() -> None:
    base, target = signed("1\n"), signed("2\n")
    other = Document.parse(signed("2\n", OTHER_SEED))
    p = Patch.parse(sjsonl.diff(base, target))
    forged = Patch(p.base, p.target, p.rm, p.lines, p.key, other.sig)
    with pytest.raises(errors.SignatureVerificationError):
        Document.parse(base).apply(forged)


def test_over_matching_prefix_fails_closed() -> None:
    base = Document.parse(signed("1\n2\n3\n"))
    target = Document.parse(signed("1\n2\n"))
    p = base.diff(target)
    # A prefix of "" deletes everything, which won't match the target.
    greedy = Patch(p.base, p.target, ("",), p.lines, p.key, p.sig)
    with pytest.raises(errors.TargetMismatchError):
        base.apply(greedy)


def test_unmatched_prefix_is_an_error() -> None:
    base = Document.parse(signed("1\n"))
    p = Patch(base.hash, base.hash, ("f" * 64 + "0",), ())
    with pytest.raises(errors.UnmatchedPrefixError):
        base.apply(p)


def test_patch_adding_existing_line_is_rejected() -> None:
    base = Document.parse(signed("1\n2\n"))
    one = Document.from_jsonl("1\n")
    p = Patch(base.hash, base.hash, (), one.lines)
    with pytest.raises(errors.DuplicateLineError, match="already in base"):
        base.apply(p)


def test_unsigned_patch_yields_unsigned_document() -> None:
    base, target = signed("1\n2\n"), signed("2\n3\n")
    patch = sjsonl.diff(base, target, signed=False)
    assert b'"key"' not in patch and b'"sig"' not in patch
    result, info = sjsonl.apply_patch(base, patch)
    assert info.signer_key is None and info.signer_id is None
    assert info.hash == sjsonl.verify(target).hash
    assert not result.startswith(b'{"sjsonl"')
    assert Document.from_jsonl(result).hash == info.hash


def test_signed_diff_requires_signed_target() -> None:
    base = Document.parse(signed("1\n"))
    with pytest.raises(errors.MissingSignatureError):
        base.diff(Document.from_jsonl("2\n"))
    assert not base.diff(Document.from_jsonl("2\n"), signed=False).signed


def test_random_round_trips() -> None:
    rng = random.Random(0)
    pool = [sjsonl.dumps_line({"i": i, "x": rng.random()}) for i in range(300)]
    for _ in range(50):
        a = Document.from_lines(rng.sample(pool, rng.randint(0, 150))).sign(SEED)
        b = Document.from_lines(rng.sample(pool, rng.randint(0, 150))).sign(SEED)
        p = Patch.parse(a.diff(b).to_bytes())
        assert a.apply(p) == b


# --------------------------------------------------------------------------
# Prefixes


def brute_force_prefixes(targets: set[str], all_: list[str]) -> tuple[str, ...]:
    """The reference algorithm from sjsonl-go."""
    others = [h for h in all_ if h not in targets]
    out = set()
    for t in targets:
        for n in range(1, len(t) + 1):
            if not any(o.startswith(t[:n]) for o in others):
                out.add(t[:n])
                break
        else:
            out.add(t)
    return tuple(sorted(out))


def test_unique_prefixes_match_reference() -> None:
    rng = random.Random(0)
    for _ in range(200):
        hashes = sorted({"".join(rng.choices("0123", k=6)) for _ in range(rng.randint(1, 40))})
        targets = set(rng.sample(hashes, rng.randint(0, len(hashes))))
        assert _unique_prefixes(targets, hashes) == brute_force_prefixes(targets, hashes)


def test_unique_prefix_examples() -> None:
    assert _unique_prefixes(set(), ["abc"]) == ()
    assert _unique_prefixes({"abc"}, ["abc"]) == ("a",)
    assert _unique_prefixes({"abc"}, ["abc", "abd"]) == ("abc",)
    assert _unique_prefixes({"abc", "abd"}, ["abc", "abd", "b"]) == ("a",)


# --------------------------------------------------------------------------
# Object API and helpers


def test_document_membership_and_iteration() -> None:
    doc = Document.from_jsonl('{"a": 1}\n2\n')
    line = next(iter(doc))
    assert line in doc
    assert line.hash in doc
    assert "00" * 32 not in doc
    assert 5 not in doc
    assert {ln.value() == 2 for ln in doc} == {True, False}


def test_unsigned_document_serializes_as_plain_jsonl() -> None:
    doc = Document.from_jsonl("2\n1\n")
    assert not doc.signed
    assert doc.header() is None
    assert Document.from_jsonl(doc.to_bytes()) == doc


def test_dumps_line_is_compact_and_stable() -> None:
    assert sjsonl.dumps_line({"b": [1, 2], "a": "é"}) == '{"a":"é","b":[1,2]}'
    with pytest.raises(ValueError):
        sjsonl.dumps_line(float("nan"))


def test_private_key_round_trip() -> None:
    key = sjsonl.generate_private_key()
    encoded = sjsonl.dump_private_key(key)
    assert sjsonl.dump_private_key(sjsonl.load_private_key(encoded + "\n")) == encoded
    assert sjsonl.dump_private_key(SEED) == base64.b64encode(SEED).decode()


@pytest.mark.parametrize("bad", ["", "abcd", "!!!!", base64.b64encode(b"x" * 64).decode()])
def test_load_private_key_rejects_bad_input(bad: str) -> None:
    with pytest.raises(ValueError):
        sjsonl.load_private_key(bad)


def test_bad_seed_type_and_length() -> None:
    with pytest.raises(ValueError):
        sjsonl.sign("1\n", b"short")
    with pytest.raises(TypeError):
        sjsonl.sign("1\n", "not a key")  # type: ignore[arg-type]


def test_all_errors_are_value_errors() -> None:
    assert issubclass(sjsonl.SJSONLError, ValueError)
    with pytest.raises(sjsonl.SJSONLError):
        sjsonl.verify(b"junk")
