"""pydevirt.core.loader — read ``.py`` / ``.pyc`` / raw-marshal blobs.

Single responsibility: turn a path or a byte string into a typed :class:`CodeBlob`
without executing anything. ``.pyc`` headers vary by Python era (PEP 552); we keep
one authoritative magic→(version, header-length) table here so the rest of the
tool never has to guess, and never leans on the *host* interpreter's layout to
reason about a *target* built by a different version.

Failure modes handled: unknown magic (probe header lengths), truncated marshal,
non-text / non-code blobs (reported, not crashed).
"""

from __future__ import annotations

import marshal
import struct
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import CodeType
from typing import Optional


class BlobKind(str, Enum):
    SOURCE = "source"
    PYC = "pyc"
    MARSHAL = "marshal"
    UNKNOWN = "unknown"


# magic int (little-endian u16 that precedes b"\r\n") -> (version, header bytes)
#   2.7 .. 3.2 : magic(4) + mtime(4)                     = 8
#   3.3 .. 3.6 : magic(4) + mtime(4) + source_size(4)    = 12
#   3.7+       : magic(4) + bitfield(4) + mtime(4) + size = 16   (PEP 552)
MAGIC_TABLE: dict[int, tuple[str, int]] = {
    62211: ("2.7", 8),
    3379: ("3.6", 12),
    3390: ("3.7", 16), 3391: ("3.7", 16), 3392: ("3.7", 16), 3394: ("3.7", 16),
    3400: ("3.8", 16), 3401: ("3.8", 16), 3410: ("3.8", 16), 3411: ("3.8", 16),
    3412: ("3.8", 16), 3413: ("3.8", 16),
    3420: ("3.9", 16), 3421: ("3.9", 16), 3422: ("3.9", 16), 3423: ("3.9", 16),
    3424: ("3.9", 16), 3425: ("3.9", 16),
    3430: ("3.10", 16), 3431: ("3.10", 16), 3432: ("3.10", 16), 3433: ("3.10", 16),
    3434: ("3.10", 16), 3435: ("3.10", 16), 3436: ("3.10", 16),
    3438: ("3.11", 16), 3439: ("3.11", 16),
    3450: ("3.12", 16), 3451: ("3.12", 16),
    3495: ("3.13", 16), 3531: ("3.13", 16),
}


@dataclass
class CodeBlob:
    """The loader's output. Exactly one of ``code``/``source`` is usually set."""

    path: str
    kind: BlobKind
    raw: bytes
    version: Optional[str] = None
    code: Optional[CodeType] = None
    source: Optional[str] = None
    notes: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.notes is None:
            self.notes = []


class LoadError(Exception):
    """Raised only when a blob cannot be interpreted at all."""


def looks_like_pyc(blob: bytes) -> bool:
    return len(blob) >= 4 and blob[2:4] == b"\r\n"


def read_pyc(blob: bytes) -> tuple[Optional[str], Optional[CodeType], list[str]]:
    """Return ``(version, code_or_None, notes)`` from a ``.pyc`` byte string.

    ``marshal.loads`` only *reconstructs* the data structure (a code object); it
    does not run code. If the magic is unknown we probe 16/12/8-byte headers.
    """
    notes: list[str] = []
    magic = struct.unpack("<H", blob[0:2])[0]
    version, header = MAGIC_TABLE.get(magic, (None, 0))
    if version is None:
        notes.append(f"unknown .pyc magic {magic}; probing header lengths")
    for hlen in ([header] if header else [16, 12, 8]):
        try:
            obj = marshal.loads(blob[hlen:])
        except Exception as exc:  # noqa: BLE001 — probing is expected to miss
            notes.append(f"marshal failed at header={hlen}: {exc!r}")
            continue
        if isinstance(obj, CodeType):
            return version, obj, notes
        notes.append(f"header={hlen} yielded {type(obj).__name__}, not code")
    return version, None, notes


def _is_probably_text(blob: bytes) -> bool:
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not text:
        return True
    # mostly printable / whitespace => source
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
    return printable / len(text) > 0.90


def load_bytes(blob: bytes, path: str = "<memory>") -> CodeBlob:
    if looks_like_pyc(blob):
        version, code, notes = read_pyc(blob)
        kind = BlobKind.PYC if code is not None else BlobKind.UNKNOWN
        return CodeBlob(path, kind, blob, version=version, code=code, notes=notes)

    if _is_probably_text(blob):
        return CodeBlob(path, BlobKind.SOURCE, blob, source=blob.decode("utf-8"))

    # last resort: a bare marshal payload (no pyc header)
    try:
        obj = marshal.loads(blob)
    except Exception as exc:  # noqa: BLE001
        return CodeBlob(path, BlobKind.UNKNOWN, blob, notes=[f"not pyc/text/marshal: {exc!r}"])
    if isinstance(obj, CodeType):
        return CodeBlob(path, BlobKind.MARSHAL, blob, code=obj)
    return CodeBlob(path, BlobKind.UNKNOWN, blob, notes=[f"marshal gave {type(obj).__name__}"])


def load_path(path: str | Path) -> CodeBlob:
    p = Path(path)
    if not p.exists():
        raise LoadError(f"no such file: {p}")
    return load_bytes(p.read_bytes(), str(p))
