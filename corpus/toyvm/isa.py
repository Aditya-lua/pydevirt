"""Toy-VM instruction set — the GROUND TRUTH for corpus samples.

A stack machine with ~28 opcodes. Jump targets are absolute byte offsets into
the (rolling-XOR-encoded) code stream, stored big-endian in 2 bytes. Operand
field widths are declared here so the encoder and any decoder agree.

This module is ground truth for *validating* pydevirt — the tool itself must
REDISCOVER these semantics from a protected sample, never import this table.
"""

from __future__ import annotations

from enum import IntEnum


class Op(IntEnum):
    NOP = 0
    LOAD_CONST = 1      # operand: const index (1)
    LOAD_LOCAL = 2      # operand: local index (1)
    STORE_LOCAL = 3     # operand: local index (1)
    POP = 4
    DUP = 5

    ADD = 10
    SUB = 11
    MUL = 12
    FLOORDIV = 13
    MOD = 14
    NEG = 15

    LT = 20
    LE = 21
    GT = 22
    GE = 23
    EQ = 24
    NE = 25
    NOT = 26

    JUMP = 30           # operand: target (2)
    JUMP_IF_FALSE = 31  # operand: target (2)
    JUMP_IF_TRUE = 32   # operand: target (2)

    BUILD_LIST = 40     # operand: count (1)
    GET_ITER = 41
    FOR_ITER = 42       # operand: target (2)
    INDEX = 43

    CALL_BUILTIN = 50   # operands: builtin id (1), argc (1)
    PRINT = 60
    RETURN = 61


# operand field widths in bytes (big-endian), empty tuple = no operand
OPERANDS: dict[int, tuple[int, ...]] = {
    Op.NOP: (),
    Op.LOAD_CONST: (1,),
    Op.LOAD_LOCAL: (1,),
    Op.STORE_LOCAL: (1,),
    Op.POP: (),
    Op.DUP: (),
    Op.ADD: (), Op.SUB: (), Op.MUL: (), Op.FLOORDIV: (), Op.MOD: (), Op.NEG: (),
    Op.LT: (), Op.LE: (), Op.GT: (), Op.GE: (), Op.EQ: (), Op.NE: (), Op.NOT: (),
    Op.JUMP: (2,), Op.JUMP_IF_FALSE: (2,), Op.JUMP_IF_TRUE: (2,),
    Op.BUILD_LIST: (1,),
    Op.GET_ITER: (),
    Op.FOR_ITER: (2,),
    Op.INDEX: (),
    Op.CALL_BUILTIN: (1, 1),
    Op.PRINT: (),
    Op.RETURN: (),
}

# builtins callable via CALL_BUILTIN, addressed by id (index)
BUILTIN_NAMES = ["len", "range", "abs", "min", "max", "sum"]

# operands that are jump targets (need label resolution) -> which field index
JUMP_FIELDS: dict[int, int] = {Op.JUMP: 0, Op.JUMP_IF_FALSE: 0, Op.JUMP_IF_TRUE: 0, Op.FOR_ITER: 0}

NAME_TO_OP = {op.name: int(op) for op in Op}
OP_TO_NAME = {int(op): op.name for op in Op}


def instr_size(op: int) -> int:
    return 1 + sum(OPERANDS[Op(op)])
