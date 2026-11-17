# sjsonl

A Python implementation of [Signed JSONL (SJSONL)](https://openrevs.org/specs/sjsonl/), a simple format for signing, diffing and patching JSON data.

SJSONL structures documents as [JSON Lines](https://jsonlines.org) and treats each document as a *set* of lines. Signing reduces to hashing lines and diffing reduces to set operations, with no canonicalization and no signature-embedding tricks. See the [specification](https://openrevs.org/specs/sjsonl/) for the format and its rationale.

This library implements SJSONL version 0.1 and is byte-for-byte compatible with [sjsonl-go](https://github.com/openrevs/sjsonl-go).

## Install

```bash
uv add sjsonl      # or: pip install sjsonl
```

Requires Python 3.10+. The only dependency is [`cryptography`](https://cryptography.io).

## Usage

### Bytes in, bytes out

```python
import sjsonl

key = sjsonl.generate_private_key()

signed, info = sjsonl.sign(b'{"name": "Alice"}\n{"name": "Bob"}\n', key)
info = sjsonl.verify(signed)  # raises sjsonl.SJSONLError if invalid
info.hash  # document hash (hex)
info.signer_id  # SHA256 of the signer's public key (hex)

patch = sjsonl.diff(old_signed, new_signed)  # signed patch
patch = sjsonl.diff(old_signed, new_signed, signed=False)
result, info = sjsonl.apply_patch(old_signed, patch)  # verified result
```

Inputs may be `bytes` or `str`; outputs are `bytes`.

### Documents and patches

```python
from sjsonl import Document, Patch, dumps_line

doc = Document.from_lines([dumps_line(r) for r in records]).sign(key)
doc = Document.parse(signed_bytes)  # parses and verifies
doc.hash, doc.info, len(doc)
for line in doc:  # sorted by line hash
    line.hash, line.data, line.value()

patch = old_doc.diff(new_doc)  # Patch
new_doc = old_doc.apply(Patch.parse(patch_bytes))
patch.to_bytes(), new_doc.to_bytes()
```

`Document` and `Patch` are immutable. A document built with `Document.from_jsonl` or `from_lines` is unsigned until you call `.sign()`, and an unsigned document serializes as plain JSONL with no header line.

### Keys

Private keys are `cryptography` `Ed25519PrivateKey` objects, and anywhere a key is accepted you can also pass a raw 32-byte seed. To store a key, for example in a Django setting or an environment variable:

```python
encoded = sjsonl.dump_private_key(key)  # base64 of the 32-byte seed
key = sjsonl.load_private_key(encoded)
```

This is the same format the Go CLI uses for `sjsonl keygen` and `SJSONL_PRIVATE_KEY`.

### Encoding lines

SJSONL hashes lines exactly as written, so the same value encoded two ways counts as two different lines. Both are valid, but re-encoding an unchanged record makes it appear in every patch. `sjsonl.dumps_line(value)` produces compact, key-sorted, stable JSON that follows the spec's encoding recommendations.

### Errors

Every error is a subclass of `sjsonl.SJSONLError`, which is itself a `ValueError`. The specific classes are in `sjsonl.errors`, for example `SignatureVerificationError`, `BaseMismatchError` and `DuplicateLineError`. Line errors carry a 1-based `lineno`.

## Development

```bash
uv sync                  # create .venv with dev dependencies
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv build                 # sdist + wheel in dist/
```

`tests/vectors/` holds fixtures produced by sjsonl-go, so that both implementations stay byte-compatible.

## Releasing

Releases go to PyPI through [trusted publishing](https://docs.pypi.org/trusted-publishers/), with no API tokens. Bump the version with `uv version --bump patch` (or `minor`/`major`), commit, tag, and publish a GitHub release. The `publish.yml` workflow then builds and uploads the release.

## License

MIT
