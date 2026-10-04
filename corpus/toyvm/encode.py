"""Toy-VM assembler + obfuscation layer.

Takes a symbolic program (list of ``(MNEMONIC, *operands)`` tuples, plus
``("LABEL", name)`` pseudo-ops) and produces:
  * ``code``   : rolling-XOR-encoded byte stream (key depends on byte position),
  * ``consts`` : a list of per-index XOR-encrypted ``marshal`` blobs (decrypted
                 lazily by the interpreter),
  * the ``seed`` and ``const_key`` needed to decode them.

Jump operands may be label strings; they're resolved to absolute byte offsets
in a first pass. This mirrors the real-world shape pydevirt must defeat: encoded
operands, a position-dependent key schedule, and an encrypted const pool.
"""

from __future__ import annotations

import marshal
from dataclasses import dataclass
from typing import Any

from .isa import JUMP_FIELDS, NAME_TO_OP, OPERANDS, Op


@dataclass
class Program:
    code: bytes
    consts: list[bytes]
    seed: int
    const_key: bytes
    nlocals: int


class AssembleError(Exception):
    pass


def _emit_field(value: int, width: int) -> bytes:
    if not (0 <= value < (1 << (8 * width))):
        raise AssembleError(f"operand {value} does not fit in {width} byte(s)")
    return value.to_bytes(width, "big")


def rolling_xor(data: bytes, seed: int) -> bytes:
    """Symmetric: encode and decode are the same op. key(pos) = (seed+pos)&0xFF."""
    return bytes(b ^ ((seed + i) & 0xFF) for i, b in enumerate(data))


def _encrypt_const(value: Any, key: bytes) -> bytes:
    raw = marshal.dumps(value)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))


def assemble(
    program: list[tuple],
    consts: list[Any],
    nlocals: int,
    *,
    seed: int = 0x5A,
    const_key: bytes = b"\x9e\x37\x79\xb9",
) -> Program:
    # a program item is either a bare mnemonic string ("ADD") or a tuple
    # ("LOAD_CONST", 0) / ("LABEL", name). Normalize to (head, *fields).
    def norm(item) -> tuple:
        if isinstance(item, str):
            return (item,)
        return tuple(item)

    # pass 1: byte offset of each instruction + label table
    offsets: list[int] = []
    labels: dict[str, int] = {}
    pos = 0
    for item in program:
        head, *_ = norm(item)
        if head == "LABEL":
            labels[norm(item)[1]] = pos
            offsets.append(pos)
            continue
        if head not in NAME_TO_OP:
            raise AssembleError(f"unknown mnemonic {head!r}")
        op = NAME_TO_OP[head]
        offsets.append(pos)
        pos += 1 + sum(OPERANDS[Op(op)])

    # pass 2: emit raw bytes with labels resolved
    raw = bytearray()
    for item in program:
        head, *fields = norm(item)
        if head == "LABEL":
            continue
        op = NAME_TO_OP[head]
        widths = OPERANDS[Op(op)]
        if len(fields) != len(widths):
            raise AssembleError(f"{head}: expected {len(widths)} operand(s), got {len(fields)}")
        raw.append(op)
        jfield = JUMP_FIELDS.get(op)
        for idx, (val, width) in enumerate(zip(fields, widths)):
            if jfield is not None and idx == jfield:
                if isinstance(val, str):
                    if val not in labels:
                        raise AssembleError(f"undefined label {val!r}")
                    val = labels[val]
            raw.extend(_emit_field(int(val), width))

    code = rolling_xor(bytes(raw), seed)
    enc_consts = [_encrypt_const(c, const_key) for c in consts]
    return Program(code=code, consts=enc_consts, seed=seed, const_key=const_key, nlocals=nlocals)
