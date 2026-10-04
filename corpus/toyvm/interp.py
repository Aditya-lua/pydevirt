"""Toy-VM interpreter — the dispatch loop pydevirt must devirtualize.

``_run`` is the canonical loop. ``protect.py`` embeds *its source text* into each
standalone protected module (via :func:`loop_source`) so the thing we analyze and
the thing we run for sanity checks can never drift apart.
"""

from __future__ import annotations

import inspect
from typing import Any


def _run(code, consts, seed, const_key, nlocals, args):  # noqa: C901 - a VM loop is one big switch
    import marshal

    stack = []
    L = list(args) + [None] * (nlocals - len(args))
    _const_cache = {}

    def dec_const(i):
        if i not in _const_cache:
            raw = bytes(b ^ const_key[j % len(const_key)] for j, b in enumerate(consts[i]))
            _const_cache[i] = marshal.loads(raw)
        return _const_cache[i]

    def rd(p):
        return code[p] ^ ((seed + p) & 0xFF)

    def rd2(p):
        return (rd(p) << 8) | rd(p + 1)

    BUILTINS = [len, range, abs, min, max, sum]
    pc = 0
    while True:
        op = rd(pc); pc += 1
        if op == 0:            # NOP
            pass
        elif op == 1:          # LOAD_CONST
            i = rd(pc); pc += 1; stack.append(dec_const(i))
        elif op == 2:          # LOAD_LOCAL
            i = rd(pc); pc += 1; stack.append(L[i])
        elif op == 3:          # STORE_LOCAL
            i = rd(pc); pc += 1; L[i] = stack.pop()
        elif op == 4:          # POP
            stack.pop()
        elif op == 5:          # DUP
            stack.append(stack[-1])
        elif op == 10:         # ADD
            b = stack.pop(); a = stack.pop(); stack.append(a + b)
        elif op == 11:         # SUB
            b = stack.pop(); a = stack.pop(); stack.append(a - b)
        elif op == 12:         # MUL
            b = stack.pop(); a = stack.pop(); stack.append(a * b)
        elif op == 13:         # FLOORDIV
            b = stack.pop(); a = stack.pop(); stack.append(a // b)
        elif op == 14:         # MOD
            b = stack.pop(); a = stack.pop(); stack.append(a % b)
        elif op == 15:         # NEG
            a = stack.pop(); stack.append(-a)
        elif op == 20:         # LT
            b = stack.pop(); a = stack.pop(); stack.append(a < b)
        elif op == 21:         # LE
            b = stack.pop(); a = stack.pop(); stack.append(a <= b)
        elif op == 22:         # GT
            b = stack.pop(); a = stack.pop(); stack.append(a > b)
        elif op == 23:         # GE
            b = stack.pop(); a = stack.pop(); stack.append(a >= b)
        elif op == 24:         # EQ
            b = stack.pop(); a = stack.pop(); stack.append(a == b)
        elif op == 25:         # NE
            b = stack.pop(); a = stack.pop(); stack.append(a != b)
        elif op == 26:         # NOT
            a = stack.pop(); stack.append(not a)
        elif op == 30:         # JUMP
            pc = rd2(pc)
        elif op == 31:         # JUMP_IF_FALSE
            t = rd2(pc); pc += 2
            if not stack.pop():
                pc = t
        elif op == 32:         # JUMP_IF_TRUE
            t = rd2(pc); pc += 2
            if stack.pop():
                pc = t
        elif op == 40:         # BUILD_LIST
            n = rd(pc); pc += 1
            items = [stack.pop() for _ in range(n)][::-1]
            stack.append(items)
        elif op == 41:         # GET_ITER
            stack.append(iter(stack.pop()))
        elif op == 42:         # FOR_ITER
            t = rd2(pc); pc += 2
            try:
                stack.append(next(stack[-1]))
            except StopIteration:
                stack.pop(); pc = t
        elif op == 43:         # INDEX
            i = stack.pop(); c = stack.pop(); stack.append(c[i])
        elif op == 50:         # CALL_BUILTIN
            bid = rd(pc); pc += 1
            argc = rd(pc); pc += 1
            a = [stack.pop() for _ in range(argc)][::-1]
            stack.append(BUILTINS[bid](*a))
        elif op == 60:         # PRINT
            print(stack.pop())
        elif op == 61:         # RETURN
            return stack.pop()
        else:
            raise RuntimeError("bad op %d @ pc %d" % (op, pc))


def loop_source() -> str:
    """Source text of :func:`_run`, for embedding into protected modules."""
    return inspect.getsource(_run)


def run_program(prog, args: tuple) -> Any:
    """Run an assembled :class:`~corpus.toyvm.encode.Program` directly."""
    return _run(prog.code, prog.consts, prog.seed, prog.const_key, prog.nlocals, args)
