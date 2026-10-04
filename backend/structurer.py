"""pydevirt.backend.structurer — CFG -> structured Python statements.

Dominator/post-dominator-guided recovery of ``while`` and ``if`` from the CFG,
without ``goto``. A natural-loop header becomes a ``while`` (condition read off
the header's branch by which successor stays in the loop); any other two-way
branch becomes an ``if`` whose join is the branch's immediate post-dominator.

Scope: reducible graphs with the loop/if/return shapes the corpus produces.
Irreducible flow or unhandled terminators degrade to a labeled note rather than
wrong code (callers see it via IRFunction.unrecovered / emitted Pass).
"""

from __future__ import annotations

import ast

from ir.cfg import _dominators
from ir.nodes import Branch, ForIter, Goto, IRFunction, Return

EXIT = None


def _postdom(fn: IRFunction, succs: dict[int, list]) -> dict:
    fsucc = {n: list(succs.get(n, [])) for n in fn.blocks}
    for n, b in fn.blocks.items():
        if isinstance(b.term, Return) or not fsucc[n]:
            if EXIT not in fsucc[n]:
                fsucc[n].append(EXIT)
    rsucc: dict = {EXIT: []}
    for n in fn.blocks:
        rsucc.setdefault(n, [])
    for n, ss in fsucc.items():
        for s in ss:
            rsucc.setdefault(s, []).append(n)
    nodes = [EXIT] + list(fn.blocks)
    return _dominators(EXIT, rsucc, nodes)


def structure(fn: IRFunction, cfg) -> list:
    from .pyemit import expr_to_ast, stmt_to_ast  # lazy: avoid import cycle

    ipost = _postdom(fn, cfg.succs)
    done_headers: set = set()

    def invert(cond):
        return ast.UnaryOp(ast.Not(), cond)

    def seq(node, stop) -> list:
        out: list = []
        guard: set = set()
        while node is not None and node != stop:
            if node in guard:
                break
            guard.add(node)

            if node in cfg.loops and node not in done_headers:
                done_headers.add(node)
                node = emit_loop(node, out)
                continue

            blk = fn.blocks[node]
            out.extend(stmt_to_ast(s) for s in blk.stmts)
            term = blk.term
            if isinstance(term, Return):
                out.append(ast.Return(expr_to_ast(term.value)))
                node = None
            elif isinstance(term, Goto):
                node = term.target
            elif isinstance(term, Branch):
                node = emit_if(node, term, out, stop)
            elif isinstance(term, ForIter):
                node = emit_for(node, term, out)
            else:
                node = None
        return out

    def emit_loop(h, out):
        blk = fn.blocks[h]
        out.extend(stmt_to_ast(s) for s in blk.stmts)
        term = blk.term
        loop = cfg.loops[h]
        if isinstance(term, Branch):
            tt, ft = term.true_target, term.false_target
            if tt in loop and ft not in loop:
                cond, body_entry, follow = expr_to_ast(term.cond), tt, ft
            elif ft in loop and tt not in loop:
                cond, body_entry, follow = invert(expr_to_ast(term.cond)), ft, tt
            else:
                cond, body_entry, follow = ast.Constant(True), tt, None
            body = seq(body_entry, stop=h)
            out.append(ast.While(test=cond, body=body or [ast.Pass()], orelse=[]))
            return follow
        if isinstance(term, ForIter):
            return emit_for(h, term, out)
        # degenerate infinite loop
        succ = cfg.succs.get(h, [None])
        body = seq(succ[0] if succ else None, stop=h)
        out.append(ast.While(test=ast.Constant(True), body=body or [ast.Pass()], orelse=[]))
        return None

    def emit_if(node, term, out, stop):
        join = ipost.get(node)
        inner_stop = join if join is not None else stop
        then_body = seq(term.true_target, stop=inner_stop)
        else_body = seq(term.false_target, stop=inner_stop)
        out.append(ast.If(test=expr_to_ast(term.cond),
                          body=then_body or [ast.Pass()], orelse=else_body))
        return join

    def emit_for(node, term, out):
        # for <var> in <iterator>:  (iterator was materialized as a Name)
        loop = cfg.loops.get(node, set())
        body = seq(term.body, stop=node)
        target = ast.Name(term.var or "_", ast.Store())
        out.append(ast.For(target=target, iter=ast.Name(term.iterator, ast.Load()),
                           body=body or [ast.Pass()], orelse=[]))
        return term.exit_ if term.exit_ not in loop else None

    return seq(fn.entry, stop=None)
