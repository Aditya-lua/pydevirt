"""pydevirt.ir.lift — decoded VM instructions -> stack-free IR blocks.

We split the decoded stream into basic blocks (leaders = offset 0, every jump
target, and every instruction after a control transfer), then simulate the VM
stack symbolically within each block so the result is three-address-ish IR with
no stack. Parameters are inferred by a light liveness pass (a local read before
it is written on entry is a parameter).
"""

from __future__ import annotations

from typing import Optional

from vm.decode import Decoded, VMInstr
from vm.semantics import SemInfo, SemOp

from .nodes import (Assign, BinOp, Block, Branch, Call, Compare, Const, ForIter,
                    Goto, IRFunction, IterNext, ListLit, Name, Print, Return,
                    Subscript, UnOp)


def _refs(e) -> set:
    """Variable names an IR expression reads."""
    if isinstance(e, Name):
        return {e.id}
    if isinstance(e, Const):
        return set()
    if isinstance(e, BinOp):
        return _refs(e.left) | _refs(e.right)
    if isinstance(e, Compare):
        return _refs(e.left) | _refs(e.right)
    if isinstance(e, UnOp):
        return _refs(e.operand)
    if isinstance(e, Call):
        out = set()
        for a in e.args:
            out |= _refs(a)
        return out
    if isinstance(e, Subscript):
        return _refs(e.value) | _refs(e.index)
    if isinstance(e, ListLit):
        out = set()
        for a in e.elts:
            out |= _refs(a)
        return out
    if isinstance(e, IterNext):
        return {e.iterator}
    return set()

_BIN = {SemOp.ADD: "+", SemOp.SUB: "-", SemOp.MUL: "*", SemOp.FLOORDIV: "//", SemOp.MOD: "%"}
_CMP = {SemOp.CMP_LT: "<", SemOp.CMP_LE: "<=", SemOp.CMP_GT: ">", SemOp.CMP_GE: ">=",
        SemOp.CMP_EQ: "==", SemOp.CMP_NE: "!="}
_CONTROL = {SemOp.JUMP, SemOp.JUMP_IF_FALSE, SemOp.JUMP_IF_TRUE, SemOp.RETURN, SemOp.FOR_ITER}


class LiftError(Exception):
    pass


def _local_name(i: int) -> str:
    return f"v{i}"


def _leaders(decoded: Decoded, opmap: dict[int, SemInfo]) -> list[int]:
    offsets = [ins.offset for ins in decoded.instrs]
    by_off = {ins.offset: ins for ins in decoded.instrs}
    order = {off: k for k, off in enumerate(offsets)}
    leaders = {0}
    for ins in decoded.instrs:
        sem = opmap[ins.op].op
        if sem in (SemOp.JUMP, SemOp.JUMP_IF_FALSE, SemOp.JUMP_IF_TRUE, SemOp.FOR_ITER):
            target = ins.operands[0]
            leaders.add(target)
            nxt = ins.offset + ins.size
            if nxt in by_off:
                leaders.add(nxt)
        elif sem is SemOp.RETURN:
            nxt = ins.offset + ins.size
            if nxt in by_off:
                leaders.add(nxt)
    return sorted(l for l in leaders if l in by_off)


def _infer_params(decoded: Decoded, opmap: dict[int, SemInfo], nlocals: int) -> list[str]:
    """Linear approximation of liveness-on-entry: a local pushed before it is
    stored is a parameter."""
    stored: set[int] = set()
    params: list[int] = []
    for ins in decoded.instrs:
        sem = opmap[ins.op].op
        if sem is SemOp.PUSH_LOCAL:
            idx = ins.operands[0]
            if idx not in stored and idx not in params:
                params.append(idx)
        elif sem is SemOp.STORE_LOCAL:
            stored.add(ins.operands[0])
    return [_local_name(i) for i in sorted(params)]


def lift(decoded: Decoded, opmap: dict[int, SemInfo], const_values: dict[int, object],
         nlocals: int, name: str = "run") -> IRFunction:
    leaders = _leaders(decoded, opmap)
    leader_set = set(leaders)
    instrs = decoded.instrs
    index = {ins.offset: k for k, ins in enumerate(instrs)}

    # group instructions into blocks
    blocks: dict[int, Block] = {}
    unrecovered: list[str] = []
    for bi, start in enumerate(leaders):
        k = index[start]
        seq: list[VMInstr] = []
        while k < len(instrs):
            ins = instrs[k]
            if ins.offset != start and ins.offset in leader_set:
                break
            seq.append(ins)
            k += 1
            if opmap[ins.op].op in _CONTROL:
                break
        nxt = instrs[k].offset if k < len(instrs) else None
        blk = _lift_block(seq, opmap, const_values, nxt, unrecovered)
        blocks[start] = blk

    params = _infer_params(decoded, opmap, nlocals)
    return IRFunction(name=name, params=params, blocks=blocks, entry=leaders[0],
                      unrecovered=unrecovered)


def _lift_block(seq, opmap, const_values, fallthrough: Optional[int], unrecovered: list) -> Block:
    off = seq[0].offset if seq else 0
    blk = Block(offset=off)
    stack: list = []
    tmp = [0]

    def pop():
        if not stack:
            raise LiftError(f"stack underflow @ {off}")
        return stack.pop()

    def spill_writes(target: str) -> None:
        """Before writing ``target``, materialize any pending stack value that
        reads it, so later emission can't see the clobbered value."""
        for i, e in enumerate(stack):
            if target in _refs(e):
                name = f"_t{tmp[0]}"; tmp[0] += 1
                blk.stmts.append(Assign(name, e))
                stack[i] = Name(name)

    for ins in seq:
        info = opmap[ins.op]
        sem = info.op
        try:
            if sem is SemOp.NOP:
                pass
            elif sem is SemOp.PUSH_CONST:
                stack.append(Const(const_values[ins.operands[0]]))
            elif sem is SemOp.PUSH_LOCAL:
                stack.append(Name(_local_name(ins.operands[0])))
            elif sem is SemOp.STORE_LOCAL:
                target = _local_name(ins.operands[0])
                value = pop()
                spill_writes(target)
                blk.stmts.append(Assign(target, value))
            elif sem is SemOp.POP:
                pop()
            elif sem is SemOp.DUP:
                stack.append(stack[-1])
            elif sem in _BIN:
                r = pop(); l = pop()
                if info.swapped:
                    l, r = r, l
                stack.append(BinOp(_BIN[sem], l, r))
            elif sem in _CMP:
                r = pop(); l = pop()
                if info.swapped:
                    l, r = r, l
                stack.append(Compare(_CMP[sem], l, r))
            elif sem is SemOp.NEG:
                stack.append(UnOp("neg", pop()))
            elif sem is SemOp.NOT:
                stack.append(UnOp("not", pop()))
            elif sem is SemOp.INDEX:
                i = pop(); c = pop(); stack.append(Subscript(c, i))
            elif sem is SemOp.BUILD_LIST:
                n = ins.operands[0]
                items = [pop() for _ in range(n)][::-1]
                stack.append(ListLit(tuple(items)))
            elif sem is SemOp.CALL_BUILTIN:
                bid, argc = ins.operands[0], ins.operands[1]
                args = [pop() for _ in range(argc)][::-1]
                fname = (info.builtin_names or [])[bid] if info.builtin_names and bid < len(info.builtin_names) else f"builtin{bid}"
                stack.append(Call(fname, tuple(args)))
            elif sem is SemOp.PRINT:
                blk.stmts.append(Print(pop()))
            elif sem is SemOp.GET_ITER:
                stack.append(Call("iter", (pop(),)))
            elif sem is SemOp.RETURN:
                blk.term = Return(pop()); return blk
            elif sem is SemOp.JUMP:
                blk.term = Goto(ins.operands[0]); return blk
            elif sem is SemOp.JUMP_IF_FALSE:
                cond = pop()
                blk.term = Branch(cond, true_target=ins.offset + ins.size, false_target=ins.operands[0])
                return blk
            elif sem is SemOp.JUMP_IF_TRUE:
                cond = pop()
                blk.term = Branch(cond, true_target=ins.operands[0], false_target=ins.offset + ins.size)
                return blk
            elif sem is SemOp.FOR_ITER:
                it = stack[-1] if stack else Name("_it")
                it_name = it.id if isinstance(it, Name) else "_it"
                blk.term = ForIter(iterator=it_name, var="", body=ins.offset + ins.size, exit_=ins.operands[0])
                return blk
            else:
                unrecovered.append(f"# UNRECOVERED: opcode {ins.op} @ pc {ins.offset} (evidence: {info.evidence})")
        except LiftError as e:
            unrecovered.append(f"# UNRECOVERED: {e} (opcode {ins.op} sem {sem.value})")

    blk.term = Goto(fallthrough) if fallthrough is not None else Return(Const(None))
    return blk
