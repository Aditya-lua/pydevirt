"""Unit tests for core.loader."""

from __future__ import annotations

import importlib.util
import marshal
import sys
from pathlib import Path
from types import CodeType

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.loader import BlobKind, load_bytes  # noqa: E402


def test_source_blob():
    b = b"def f(x):\n    return x + 1\n"
    cb = load_bytes(b)
    assert cb.kind is BlobKind.SOURCE
    assert cb.source and "return x + 1" in cb.source


def test_pyc_blob():
    code = compile("def f(x):\n return x*2\n", "<t>", "exec")
    blob = importlib.util.MAGIC_NUMBER + bytes(12) + marshal.dumps(code)
    cb = load_bytes(blob)
    assert cb.kind is BlobKind.PYC
    assert isinstance(cb.code, CodeType)


def test_raw_marshal_blob():
    code = compile("x = 1", "<t>", "exec")
    cb = load_bytes(marshal.dumps(code))
    assert cb.kind is BlobKind.MARSHAL
    assert isinstance(cb.code, CodeType)


def test_garbage_blob():
    cb = load_bytes(b"\x00\x01\x02\xff\xfe")
    assert cb.kind is BlobKind.UNKNOWN
    assert cb.notes


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print(f"ok  {name}")
    print("all loader tests passed")
