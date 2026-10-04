"""pydevirt.backend.pyemit — IR -> Python AST -> source.

Converts IR expressions/statements to real ``ast`` nodes, asks
:mod:`backend.structurer` for the structured function body, then ``ast.unparse``s
it and ``compile()``s the result as a sanity gate (unparseable or non-compiling
output is a bug we want to surface, not emit).
"""

from __future__ import annotations

import ast

from ir import nodes as N
from ir.cfg import build_cfg
from ir.nodes import IRFunction

from .structurer import structure

_BINOP = {"+": ast.Add, "-": ast.Sub, "*": ast.Mult, "//": ast.FloorDiv, "%": ast.Mod}
_CMPOP = {"<": ast.Lt, "<=": ast.LtE, ">": ast.Gt, ">=": ast.GtE, "==": ast.Eq, "!=": ast.NotEq}


def expr_to_ast(e) -> ast.expr:
    if isinstance(e, N.Const):
        return ast.Constant(e.value)
    if isinstance(e, N.Name):
        return ast.Name(e.id, ast.Load())
    if isinstance(e, N.BinOp):
        return ast.BinOp(expr_to_ast(e.left), _BINOP[e.op](), expr_to_ast(e.right))
    if isinstance(e, N.UnOp):
        op = ast.USub() if e.op == "neg" else ast.Not()
        return ast.UnaryOp(op, expr_to_ast(e.operand))
    if isinstance(e, N.Compare):
        return ast.Compare(expr_to_ast(e.left), [_CMPOP[e.op]()], [expr_to_ast(e.right)])
    if isinstance(e, N.Call):
        return ast.Call(ast.Name(e.func, ast.Load()), [expr_to_ast(a) for a in e.args], [])
    if isinstance(e, N.Subscript):
        return ast.Subscript(expr_to_ast(e.value), expr_to_ast(e.index), ast.Load())
    if isinstance(e, N.ListLit):
        return ast.List([expr_to_ast(x) for x in e.elts], ast.Load())
    if isinstance(e, N.IterNext):
        return ast.Name("_next", ast.Load())  # should be folded into a for-target
    raise TypeError(f"cannot emit expr {e!r}")


def stmt_to_ast(s) -> ast.stmt:
    if isinstance(s, N.Assign):
        return ast.Assign([ast.Name(s.target, ast.Store())], expr_to_ast(s.value))
    if isinstance(s, N.Print):
        return ast.Expr(ast.Call(ast.Name("print", ast.Load()), [expr_to_ast(s.value)], []))
    raise TypeError(f"cannot emit stmt {s!r}")


def build_function(fn: IRFunction, cfg) -> ast.FunctionDef:
    body = structure(fn, cfg)
    if not body:
        body = [ast.Pass()]
    args = ast.arguments(
        posonlyargs=[], args=[ast.arg(p) for p in fn.params], vararg=None,
        kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[],
    )
    node = ast.FunctionDef(name=fn.name, args=args, body=body, decorator_list=[], returns=None)
    return node


def decompile(fn: IRFunction, cfg=None) -> str:
    cfg = cfg or build_cfg(fn)
    func = build_function(fn, cfg)
    mod = ast.Module(body=[func], type_ignores=[])
    ast.fix_missing_locations(mod)
    src = ast.unparse(mod)
    if fn.unrecovered:
        src = "\n".join(fn.unrecovered) + "\n" + src
    compile(src, "<recovered>", "exec")  # sanity gate
    return src
