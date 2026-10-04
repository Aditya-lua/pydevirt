"""End-to-end pipeline tests: opcode-map recovery + differential verification.

All 7 corpus samples recover to readable Python that verifies equivalent to the
original under differential execution (while/if/return and for-loops).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from corpus.programs import by_name  # noqa: E402
from corpus.toyvm.isa import OP_TO_NAME  # noqa: E402
from corpus.toyvm.protect import emit_module  # noqa: E402
from pipeline import devirtualize  # noqa: E402
from verify.diffexec import differential  # noqa: E402

VERIFYING = ["sum_to_n", "factorial", "abs_val", "fib",
             "max_list", "count_evens", "sum_squares"]

_EXPECT = {
    'NOP': 'NOP', 'LOAD_CONST': 'PUSH_CONST', 'LOAD_LOCAL': 'PUSH_LOCAL',
    'STORE_LOCAL': 'STORE_LOCAL', 'POP': 'POP', 'DUP': 'DUP', 'ADD': 'ADD',
    'SUB': 'SUB', 'MUL': 'MUL', 'FLOORDIV': 'FLOORDIV', 'MOD': 'MOD', 'NEG': 'NEG',
    'LT': 'CMP_LT', 'LE': 'CMP_LE', 'GT': 'CMP_GT', 'GE': 'CMP_GE', 'EQ': 'CMP_EQ',
    'NE': 'CMP_NE', 'NOT': 'NOT', 'JUMP': 'JUMP', 'JUMP_IF_FALSE': 'JUMP_IF_FALSE',
    'JUMP_IF_TRUE': 'JUMP_IF_TRUE', 'BUILD_LIST': 'BUILD_LIST', 'GET_ITER': 'GET_ITER',
    'FOR_ITER': 'FOR_ITER', 'INDEX': 'INDEX', 'CALL_BUILTIN': 'CALL_BUILTIN',
    'PRINT': 'PRINT', 'RETURN': 'RETURN',
}


def test_opcode_map_fully_recovered():
    # sum_squares exercises the widest opcode set (CALL_BUILTIN, FOR_ITER, ...)
    rec = devirtualize(emit_module(by_name("sum_squares").assembled()))
    assert len(rec.opmap) == 29
    for op, info in rec.opmap.items():
        assert info.op.value == _EXPECT[OP_TO_NAME[op]], (op, OP_TO_NAME[op], info.op.value)


def test_slice_samples_verify_equivalent():
    for name in VERIFYING:
        s = by_name(name)
        orig = emit_module(s.assembled())
        rec = devirtualize(orig)
        rep = differential(orig, rec.source, s.inputs, name=name)
        assert rep.ok, rep.summary()


def test_recovered_source_is_readable():
    rec = devirtualize(emit_module(by_name("sum_to_n").assembled()))
    assert "while" in rec.source and "def run(" in rec.source
    compile(rec.source, "<t>", "exec")  # must be valid Python


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print(f"ok  {name}")
    print("all pipeline tests passed")
