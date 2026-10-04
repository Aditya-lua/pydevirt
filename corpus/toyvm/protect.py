"""Emit a standalone, self-contained protected Python module for a program.

The output module carries its own VM loop, the rolling-XOR-encoded code, the
encrypted const pool, and a ``run(*args)`` entry point. It imports nothing from
this package, so it is a faithful "family C" (custom Python VM) sample for
pydevirt to analyze end to end.
"""

from __future__ import annotations

from .encode import Program
from .interp import loop_source

_TEMPLATE = '''\
# Auto-generated protected module (toy VM). Do not edit by hand.
CODE = {code!r}
CONSTS = {consts!r}
SEED = {seed}
CONST_KEY = {const_key!r}
NLOCALS = {nlocals}

{loop_src}

def run(*args):
    return _run(CODE, CONSTS, SEED, CONST_KEY, NLOCALS, args)
'''


def emit_module(prog: Program) -> str:
    return _TEMPLATE.format(
        code=prog.code,
        consts=prog.consts,
        seed=prog.seed,
        const_key=prog.const_key,
        nlocals=prog.nlocals,
        loop_src=loop_source(),
    )
