"""pydevirt.vm.locate — find the VM structure in a protected module (static).

Heuristics (scored, with evidence) identify: the dispatch function (a
``while True`` wrapping an ``if/elif`` chain on an opcode variable), the opcode→
handler-arm map, the stack / pc / locals names, the decode helpers (the rolling
key schedule and the const decryptor), and the data globals (code / consts /
seed / const_key / nlocals) — the last bound via the thin ``run()`` wrapper's
call site so we never assume their names.

Boundary: this recognizes the common "switch-in-a-loop" stack-VM shape. Other
shapes (dict-dispatch tables, register machines) are future extensions; the
model it returns is the same, so downstream code is unaffected.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class VMNames:
    opcode_var: str
    pc_var: str
    stack_var: str
    locals_var: str
    read1: set[str] = field(default_factory=set)   # 1-byte decode fns
    read2: set[str] = field(default_factory=set)    # 2-byte decode fns
    const_fn: Optional[str] = None


@dataclass
class VMModel:
    module: ast.Module
    dispatch_fn: ast.FunctionDef
    arms: dict[int, list]                 # opcode int -> handler body (stmts)
    names: VMNames
    code: bytes
    consts: list
    seed: int
    const_key: bytes
    nlocals: int
    decode1_src: str                      # body expr source of the 1-byte reader
    decode2_src: Optional[str]            # body expr source of the 2-byte reader
    entry_name: str                       # the public wrapper, e.g. "run"
    evidence: list = field(default_factory=list)


class LocateError(Exception):
    pass


# --------------------------------------------------------------------------- #
def _is_while_true(node: ast.stmt) -> bool:
    return isinstance(node, ast.While) and isinstance(node.test, ast.Constant) and node.test.value is True


def _elif_arms(body: list) -> list[tuple[int, list]]:
    """Return [(opcode_int, handler_body), ...] from an if/elif chain testing
    ``<var> == <int>``."""
    arms: list[tuple[int, list]] = []
    stmt = next((s for s in body if isinstance(s, ast.If)), None)
    while isinstance(stmt, ast.If):
        key = _eq_int(stmt.test)
        if key is not None:
            arms.append((key, stmt.body))
        if len(stmt.orelse) == 1 and isinstance(stmt.orelse[0], ast.If):
            stmt = stmt.orelse[0]
        else:
            break
    return arms


def _eq_int(test: ast.expr) -> Optional[int]:
    if (isinstance(test, ast.Compare) and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)
            and isinstance(test.comparators[0], ast.Constant)
            and isinstance(test.comparators[0].value, int)):
        return test.comparators[0].value
    return None


def _dispatch_var(test: ast.expr) -> Optional[str]:
    if isinstance(test, ast.Compare) and isinstance(test.left, ast.Name):
        return test.left.id
    return None


def _find_dispatch_fn(mod: ast.Module) -> tuple[ast.FunctionDef, ast.While]:
    best = None
    for fn in [n for n in ast.walk(mod) if isinstance(n, ast.FunctionDef)]:
        for node in ast.walk(fn):
            if _is_while_true(node):
                arms = _elif_arms(node.body)
                if best is None or len(arms) > len(best[2]):
                    best = (fn, node, arms)
    if best is None or len(best[2]) < 4:
        raise LocateError("no dispatch loop (while-True + if/elif on int) found")
    return best[0], best[1]


# --------------------------------------------------------------------------- #
def _nested_defs(fn: ast.FunctionDef) -> dict[str, ast.FunctionDef]:
    return {n.name: n for n in fn.body if isinstance(n, ast.FunctionDef)}


def _return_expr(fn: ast.FunctionDef) -> Optional[ast.expr]:
    for n in ast.walk(fn):
        if isinstance(n, ast.Return) and n.value is not None:
            return n.value
    return None


def _classify_readers(defs: dict[str, ast.FunctionDef]) -> tuple[set[str], set[str], Optional[str], dict[str, str]]:
    """Split nested helpers into 1-byte readers, 2-byte readers, const decryptor.
    Returns (read1, read2, const_fn, {name: return_src})."""
    read1: set[str] = set()
    read2: set[str] = set()
    const_fn: Optional[str] = None
    src: dict[str, str] = {}
    for name, fn in defs.items():
        rexpr = _return_expr(fn)
        calls_marshal = any(
            isinstance(n, ast.Attribute) and n.attr == "loads" for n in ast.walk(fn)
        )
        if calls_marshal:
            const_fn = name
            continue
        if rexpr is None:
            continue
        src[name] = ast.unparse(rexpr)
        # 2-byte reader: an OR of shifted sub-reads, or two calls to a 1-byte fn
        if _looks_like_two_byte(rexpr):
            read2.add(name)
        elif _looks_like_one_byte(rexpr):
            read1.add(name)
    return read1, read2, const_fn, src


def _looks_like_two_byte(expr: ast.expr) -> bool:
    has_shift = any(isinstance(n, ast.BinOp) and isinstance(n.op, ast.LShift) for n in ast.walk(expr))
    has_or = any(isinstance(n, ast.BinOp) and isinstance(n.op, ast.BitOr) for n in ast.walk(expr))
    return has_shift and has_or


def _looks_like_one_byte(expr: ast.expr) -> bool:
    has_xor = any(isinstance(n, ast.BinOp) and isinstance(n.op, ast.BitXor) for n in ast.walk(expr))
    has_index = any(isinstance(n, ast.Subscript) for n in ast.walk(expr))
    return has_xor and has_index


# --------------------------------------------------------------------------- #
def _infer_names(dispatch_fn, loop: ast.While, arms, readers) -> VMNames:
    read1, read2, const_fn, _ = readers
    # opcode var + pc var come from the loop's opcode fetch: `op = rd(pc)`
    opcode_var = pc_var = None
    for s in loop.body:
        if (isinstance(s, ast.Assign) and len(s.targets) == 1
                and isinstance(s.targets[0], ast.Name)
                and isinstance(s.value, ast.Call)
                and isinstance(s.value.func, ast.Name)
                and s.value.func.id in (read1 | read2)
                and s.value.args and isinstance(s.value.args[0], ast.Name)):
            opcode_var = s.targets[0].id
            pc_var = s.value.args[0].id
            break
    if opcode_var is None:
        # fall back: dispatch var from the first arm test
        first_if = next((s for s in loop.body if isinstance(s, ast.If)), None)
        opcode_var = _dispatch_var(first_if.test) if first_if else "op"
        pc_var = "pc"

    # stack var: Name with both .append and .pop attribute calls
    append_names: dict[str, int] = {}
    pop_names: dict[str, int] = {}
    for node in ast.walk(dispatch_fn):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.attr == "append":
                append_names[node.func.value.id] = append_names.get(node.func.value.id, 0) + 1
            elif node.func.attr == "pop":
                pop_names[node.func.value.id] = pop_names.get(node.func.value.id, 0) + 1
    stack_candidates = [n for n in append_names if n in pop_names]
    stack_var = max(stack_candidates, key=lambda n: append_names[n] + pop_names[n]) if stack_candidates else "stack"

    # locals var: strongest signal is the name initialized from `list(args)`;
    # fall back to the most subscript-assigned name in the TOP-LEVEL body
    # (excluding the stack and anything assigned inside nested helpers).
    locals_var = None
    for s in dispatch_fn.body:
        if (isinstance(s, ast.Assign) and len(s.targets) == 1
                and isinstance(s.targets[0], ast.Name)):
            if any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "list"
                   for n in ast.walk(s.value)):
                locals_var = s.targets[0].id
                break
    if locals_var is None:
        nested = {id(n) for d in dispatch_fn.body if isinstance(d, ast.FunctionDef) for n in ast.walk(d)}
        locals_counts: dict[str, int] = {}
        for node in ast.walk(dispatch_fn):
            if id(node) in nested:
                continue
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                t = node.targets[0]
                if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and t.value.id != stack_var:
                    locals_counts[t.value.id] = locals_counts.get(t.value.id, 0) + 1
        locals_var = max(locals_counts, key=locals_counts.get) if locals_counts else "L"

    return VMNames(opcode_var, pc_var, stack_var, locals_var, read1, read2, const_fn)


# --------------------------------------------------------------------------- #
def _bind_data_globals(mod: ast.Module, dispatch_fn: ast.FunctionDef):
    """Use the wrapper `def run(*a): return DISPATCH(G0, G1, ...)` to map the
    dispatch params to module globals, then literal_eval those globals."""
    params = [a.arg for a in dispatch_fn.args.args]
    # find a call to the dispatch fn anywhere
    call = None
    entry_name = "run"
    for fn in [n for n in mod.body if isinstance(n, ast.FunctionDef)]:
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == dispatch_fn.name:
                call = node
                entry_name = fn.name
                break
        if call:
            break
    if call is None:
        raise LocateError("could not find the dispatch call site (wrapper)")

    glb = {}
    for node in mod.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                glb[node.targets[0].id] = ast.literal_eval(node.value)
            except Exception:
                pass

    bound: dict[str, object] = {}
    for param, arg in zip(params, call.args):
        if isinstance(arg, ast.Name) and arg.id in glb:
            bound[param] = glb[arg.id]
    return bound, entry_name


# --------------------------------------------------------------------------- #
def locate(module_src: str) -> VMModel:
    mod = ast.parse(module_src)
    dispatch_fn, loop = _find_dispatch_fn(mod)
    arms_list = _elif_arms(loop.body)
    arms = {op: body for op, body in arms_list}

    defs = _nested_defs(dispatch_fn)
    readers = _classify_readers(defs)
    read1, read2, const_fn, rsrc = readers
    names = _infer_names(dispatch_fn, loop, arms_list, readers)

    bound, entry_name = _bind_data_globals(mod, dispatch_fn)
    required = {"code", "consts", "seed", "const_key", "nlocals"}
    missing = required - set(bound)
    if missing:
        raise LocateError(f"could not bind data globals: missing {sorted(missing)}")

    decode1_src = next((rsrc[n] for n in read1 if n in rsrc), None)
    decode2_src = next((rsrc[n] for n in read2 if n in rsrc), None)
    if decode1_src is None:
        raise LocateError("could not recover the 1-byte decode expression")

    ev = [
        f"dispatch fn '{dispatch_fn.name}' with {len(arms)} opcode arms",
        f"opcode var '{names.opcode_var}', pc '{names.pc_var}', stack '{names.stack_var}', locals '{names.locals_var}'",
        f"readers: 1-byte={sorted(read1)} 2-byte={sorted(read2)} const='{const_fn}'",
        f"data bound via wrapper '{entry_name}': nlocals={bound['nlocals']}, |code|={len(bound['code'])}, |consts|={len(bound['consts'])}",
    ]
    return VMModel(
        module=mod, dispatch_fn=dispatch_fn, arms=arms, names=names,
        code=bound["code"], consts=bound["consts"], seed=bound["seed"],
        const_key=bound["const_key"], nlocals=bound["nlocals"],
        decode1_src=decode1_src, decode2_src=decode2_src,
        entry_name=entry_name, evidence=ev,
    )
