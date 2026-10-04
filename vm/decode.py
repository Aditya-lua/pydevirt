"""pydevirt.vm.decode — turn the encoded code stream into instructions.

Operand widths per opcode are *derived* from each handler arm (how many times it
pulls a byte/short off the stream via the recovered readers), and the rolling
key schedule is replayed by compiling the reader expressions pydevirt recovered
in :mod:`vm.locate` — never by assuming a fixed key. The const pool is decrypted
by replicating the recovered XOR-then-``marshal`` scheme.
"""

from __future__ import annotations

import ast
import marshal
from dataclasses import dataclass, field
from typing import Callable, Optional

from .locate import VMModel


@dataclass
class VMInstr:
    offset: int
    op: int
    operands: list      # decoded operand values, in order
    size: int


@dataclass
class Decoded:
    instrs: list                       # list[VMInstr]
    op_widths: dict[int, list]         # opcode -> [operand widths]
    const_values: dict[int, object]    # const index -> decrypted value
    notes: list = field(default_factory=list)


class DecodeError(Exception):
    pass


# --- operand-width recovery (source-ordered DFS over the arm body) --------- #
def _ordered_reads(body: list, read1: set[str], read2: set[str], pc_var: str) -> list[int]:
    widths: list[int] = []

    def visit(node: ast.AST) -> None:
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in (read1 | read2) and node.args
                and isinstance(node.args[0], ast.Name) and node.args[0].id == pc_var):
            widths.append(2 if node.func.id in read2 else 1)
        for child in ast.iter_child_nodes(node):
            visit(child)

    for stmt in body:
        visit(stmt)
    return widths


def recover_op_widths(model: VMModel) -> dict[int, list]:
    r1, r2, pc = model.names.read1, model.names.read2, model.names.pc_var
    return {op: _ordered_reads(body, r1, r2, pc) for op, body in model.arms.items()}


# --- decode callables from the recovered reader expressions ---------------- #
def _compile_expr(src: str, params: list[str]) -> Callable:
    code = compile(f"def _f({', '.join(params)}):\n    return {src}\n", "<decode>", "exec")
    ns: dict = {"__builtins__": {}}
    exec(code, ns)  # noqa: S102 — pure arithmetic/index expr recovered from the VM
    return ns["_f"]


def build_readers(model: VMModel):
    code, seed = model.code, model.seed
    d1 = _compile_expr(model.decode1_src, ["code", "seed", "p"])

    def read1(p: int) -> int:
        return d1(code, seed, p) & 0xFF

    if model.decode2_src is not None:
        d2 = _compile_expr(model.decode2_src, ["rd", "p"])

        def read2(p: int) -> int:
            return d2(read1, p) & 0xFFFF
    else:  # fall back to big-endian assembly from the 1-byte reader
        def read2(p: int) -> int:
            return (read1(p) << 8) | read1(p + 1)

    return read1, read2


# --- const decryption ------------------------------------------------------ #
def decrypt_consts(model: VMModel) -> dict[int, object]:
    key = model.const_key
    out: dict[int, object] = {}
    for i, blob in enumerate(model.consts):
        raw = bytes(b ^ key[j % len(key)] for j, b in enumerate(blob))
        out[i] = marshal.loads(raw)  # data only; marshal.loads does not execute
    return out


# --- linear disassembly ---------------------------------------------------- #
def disassemble(model: VMModel) -> Decoded:
    widths = recover_op_widths(model)
    read1, read2 = build_readers(model)
    consts = decrypt_consts(model)
    notes: list[str] = []

    instrs: list[VMInstr] = []
    pc = 0
    n = len(model.code)
    while pc < n:
        start = pc
        op = read1(pc)
        pc += 1
        if op not in widths:
            notes.append(f"unknown opcode {op} @ {start}; stopping linear sweep")
            instrs.append(VMInstr(start, op, [], 1))
            break
        ops: list[int] = []
        for w in widths[op]:
            ops.append(read1(pc) if w == 1 else read2(pc))
            pc += w
        instrs.append(VMInstr(start, op, ops, pc - start))
    return Decoded(instrs=instrs, op_widths=widths, const_values=consts, notes=notes)
