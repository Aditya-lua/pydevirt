"""pydevirt.vm.semantics — recover each opcode's meaning from its handler arm.

Structural classification over the handler AST (a symbolic-summary signal): we
read what the arm pops, what it pushes, how it touches locals/consts, and how it
moves the pc, then map that effect to a :class:`SemOp`. Operand *roles* are
implied by the SemOp (a fixed VM convention), so the lifter needs only the op.

Confidence is 1.0 for an exact structural match, lower when we fall back. An arm
we cannot read becomes ``SemOp.UNKNOWN`` (the pipeline degrades, not crashes).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .decode import VMInstr  # noqa: F401 - re-exported for callers' convenience
from .locate import VMModel


class SemOp(Enum):
    NOP = "NOP"
    PUSH_CONST = "PUSH_CONST"
    PUSH_LOCAL = "PUSH_LOCAL"
    STORE_LOCAL = "STORE_LOCAL"
    POP = "POP"
    DUP = "DUP"
    ADD = "ADD"; SUB = "SUB"; MUL = "MUL"; FLOORDIV = "FLOORDIV"; MOD = "MOD"
    NEG = "NEG"; NOT = "NOT"
    CMP_LT = "CMP_LT"; CMP_LE = "CMP_LE"; CMP_GT = "CMP_GT"
    CMP_GE = "CMP_GE"; CMP_EQ = "CMP_EQ"; CMP_NE = "CMP_NE"
    JUMP = "JUMP"; JUMP_IF_FALSE = "JUMP_IF_FALSE"; JUMP_IF_TRUE = "JUMP_IF_TRUE"
    BUILD_LIST = "BUILD_LIST"; GET_ITER = "GET_ITER"; FOR_ITER = "FOR_ITER"; INDEX = "INDEX"
    CALL_BUILTIN = "CALL_BUILTIN"; PRINT = "PRINT"; RETURN = "RETURN"
    UNKNOWN = "UNKNOWN"


_BINOP = {ast.Add: SemOp.ADD, ast.Sub: SemOp.SUB, ast.Mult: SemOp.MUL,
          ast.FloorDiv: SemOp.FLOORDIV, ast.Mod: SemOp.MOD}
_CMP = {ast.Lt: SemOp.CMP_LT, ast.LtE: SemOp.CMP_LE, ast.Gt: SemOp.CMP_GT,
        ast.GtE: SemOp.CMP_GE, ast.Eq: SemOp.CMP_EQ, ast.NotEq: SemOp.CMP_NE}


@dataclass
class SemInfo:
    op: SemOp
    confidence: float
    evidence: str
    swapped: bool = False          # binary/compare operand order reversed
    builtin_names: Optional[list] = None   # for CALL_BUILTIN, if the table is known


# --- small AST predicates -------------------------------------------------- #
def _is_pop(node, stack) -> bool:
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "pop" and isinstance(node.func.value, ast.Name)
            and node.func.value.id == stack and not node.args)


def _append_arg(node, stack):
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "append" and isinstance(node.func.value, ast.Name)
            and node.func.value.id == stack and len(node.args) == 1):
        return node.args[0]
    return None


def _is_peek(node, stack) -> bool:
    return (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name)
            and node.value.id == stack)


def _pop_order(body, stack) -> list[str]:
    """Names bound by ``v = stack.pop()`` in source order (index 0 = top)."""
    names: list[str] = []
    for s in body:
        if (isinstance(s, ast.Assign) and len(s.targets) == 1
                and isinstance(s.targets[0], ast.Name) and _is_pop(s.value, stack)):
            names.append(s.targets[0].id)
    return names


def _appends(body, stack) -> list:
    out = []
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        arg = _append_arg(node, stack)
        if arg is not None:
            out.append(arg)
    return out


def _has_stopiteration(body) -> bool:
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(node, ast.ExceptHandler) and node.type is not None:
            names = {n.id for n in ast.walk(node.type) if isinstance(n, ast.Name)}
            if "StopIteration" in names:
                return True
    return False


def _assigns_pc_from(body, pc, read2: set) -> bool:
    for s in body:
        if (isinstance(s, ast.Assign) and len(s.targets) == 1
                and isinstance(s.targets[0], ast.Name) and s.targets[0].id == pc
                and isinstance(s.value, ast.Call) and isinstance(s.value.func, ast.Name)
                and s.value.func.id in read2):
            return True
    return False


def _conditional_pc(body, pc, stack) -> Optional[SemOp]:
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(node, ast.If):
            sets_pc = any(
                isinstance(s, ast.Assign) and isinstance(s.targets[0], ast.Name) and s.targets[0].id == pc
                for s in node.body if isinstance(s, ast.Assign)
            )
            if not sets_pc:
                continue
            t = node.test
            if isinstance(t, ast.UnaryOp) and isinstance(t.op, ast.Not) and _is_pop(t.operand, stack):
                return SemOp.JUMP_IF_FALSE
            if _is_pop(t, stack):
                return SemOp.JUMP_IF_TRUE
    return None


def _store_local(body, stack, locals_) -> bool:
    for s in body:
        if (isinstance(s, ast.Assign) and len(s.targets) == 1
                and isinstance(s.targets[0], ast.Subscript)
                and isinstance(s.targets[0].value, ast.Name)
                and s.targets[0].value.id == locals_ and _is_pop(s.value, stack)):
            return True
    return False


# --- the classifier -------------------------------------------------------- #
def classify_arm(body: list, model: VMModel) -> SemInfo:
    n = model.names
    stack, locals_, pc = n.stack_var, n.locals_var, n.pc_var

    if not body or (len(body) == 1 and isinstance(body[0], ast.Pass)):
        return SemInfo(SemOp.NOP, 1.0, "empty / pass")

    # returns
    for s in body:
        if isinstance(s, ast.Return) and s.value is not None and _is_pop(s.value, stack):
            return SemInfo(SemOp.RETURN, 1.0, "return stack.pop()")

    # control flow
    if _has_stopiteration(body):
        return SemInfo(SemOp.FOR_ITER, 1.0, "try/except StopIteration (iterator protocol)")
    cond = _conditional_pc(body, pc, stack)
    if cond is not None:
        return SemInfo(cond, 1.0, "conditional pc assignment")
    if _assigns_pc_from(body, pc, n.read2):
        return SemInfo(SemOp.JUMP, 1.0, "pc = read2(...)")

    # local store
    if _store_local(body, stack, locals_):
        return SemInfo(SemOp.STORE_LOCAL, 1.0, "L[op] = stack.pop()")

    # print
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "print"):
            return SemInfo(SemOp.PRINT, 1.0, "print(stack.pop())")

    # push-based ops
    appends = _appends(body, stack)
    if appends:
        tops = _pop_order(body, stack)  # [top, deeper, ...]
        e = _resolve(appends[-1], body, stack)

        if isinstance(e, ast.Call) and isinstance(e.func, ast.Name) and e.func.id == n.const_fn:
            return SemInfo(SemOp.PUSH_CONST, 1.0, "push dec_const(op)")
        if isinstance(e, ast.Subscript) and isinstance(e.value, ast.Name) and e.value.id == locals_:
            return SemInfo(SemOp.PUSH_LOCAL, 1.0, "push L[op]")
        if _is_peek(e, stack):
            return SemInfo(SemOp.DUP, 1.0, "push stack[-1]")
        if isinstance(e, ast.Call) and isinstance(e.func, ast.Name) and e.func.id == "iter":
            return SemInfo(SemOp.GET_ITER, 1.0, "push iter(stack.pop())")
        if isinstance(e, ast.ListComp) or (isinstance(e, ast.Subscript) and isinstance(e.value, ast.ListComp)):
            return SemInfo(SemOp.BUILD_LIST, 0.9, "list comprehension over popped items")
        if isinstance(e, ast.Call) and isinstance(e.func, ast.Subscript):
            names = model.names
            btable = _builtin_table(model, e.func)
            return SemInfo(SemOp.CALL_BUILTIN, 0.9, "push BUILTINS[op](*args)", builtin_names=btable)
        if isinstance(e, ast.Subscript) and isinstance(e.value, ast.Name) and e.value.id in tops:
            return SemInfo(SemOp.INDEX, 1.0, "push container[index] from two pops")
        if isinstance(e, ast.BinOp) and type(e.op) in _BINOP:
            swapped = _is_swapped(e.left, e.right, tops)
            return SemInfo(_BINOP[type(e.op)], 1.0, f"push a {type(e.op).__name__} b", swapped=swapped)
        if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.USub):
            return SemInfo(SemOp.NEG, 1.0, "push -a")
        if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
            return SemInfo(SemOp.NOT, 1.0, "push not a")
        if isinstance(e, ast.Compare) and len(e.ops) == 1 and type(e.ops[0]) in _CMP:
            swapped = _is_swapped(e.left, e.comparators[0], tops)
            return SemInfo(_CMP[type(e.ops[0])], 1.0, f"push a {type(e.ops[0]).__name__} b", swapped=swapped)

    # lone pop
    if any(isinstance(s, ast.Expr) and _is_pop(s.value, stack) for s in body) and not appends:
        return SemInfo(SemOp.POP, 1.0, "bare stack.pop()")

    return SemInfo(SemOp.UNKNOWN, 0.0, "unrecognized handler shape")


def _resolve(e, body, stack):
    """If ``e`` is a Name bound in this arm to a non-pop value, return that value
    (one level of copy-propagation), so e.g. ``items = [...]; append(items)`` is
    seen as the list-comp. Pop-bound names are left as-is (they are operands)."""
    if not isinstance(e, ast.Name):
        return e
    for s in reversed(body):
        if (isinstance(s, ast.Assign) and len(s.targets) == 1
                and isinstance(s.targets[0], ast.Name) and s.targets[0].id == e.id
                and not _is_pop(s.value, stack)):
            return s.value
    return e


def _is_swapped(left, right, tops: list) -> bool:
    """tops[0]=top, tops[1]=deeper. Standard binary is (deeper <op> top)."""
    if len(tops) < 2:
        return False
    top, deeper = tops[0], tops[1]
    lname = left.id if isinstance(left, ast.Name) else None
    rname = right.id if isinstance(right, ast.Name) else None
    return lname == top and rname == deeper


def _builtin_table(model: VMModel, func_subscript) -> Optional[list]:
    """If CALL_BUILTIN indexes a module/local list literal, recover its names."""
    if not (isinstance(func_subscript, ast.Subscript) and isinstance(func_subscript.value, ast.Name)):
        return None
    tbl = func_subscript.value.id
    for node in ast.walk(model.dispatch_fn):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == tbl
                and isinstance(node.value, ast.List)):
            return [el.id if isinstance(el, ast.Name) else ast.unparse(el) for el in node.value.elts]
    return None


def recover_semantics(model: VMModel) -> dict[int, SemInfo]:
    return {op: classify_arm(body, model) for op, body in model.arms.items()}
