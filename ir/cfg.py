"""pydevirt.ir.cfg — control-flow graph, dominators, and natural loops.

Successors come from each block's terminator. Dominators use the classic
iterative (Cooper-Harvey-Kennedy) fixpoint. A back edge ``a->h`` (where ``h``
dominates ``a``) marks ``h`` as a loop header; the natural loop is the set of
nodes that reach ``a`` without passing through ``h``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .nodes import Branch, ForIter, Goto, IRFunction, Return


@dataclass
class CFG:
    entry: int
    succs: dict[int, list]
    preds: dict[int, list]
    idom: dict[int, int]
    back_edges: list           # list[(tail, header)]
    loops: dict[int, set]      # header -> set of body offsets (incl. header)


def successors(term) -> list:
    if isinstance(term, Goto):
        return [term.target]
    if isinstance(term, Branch):
        return [term.true_target, term.false_target]
    if isinstance(term, ForIter):
        return [term.body, term.exit_]
    if isinstance(term, Return):
        return []
    return []


def build_cfg(fn: IRFunction) -> CFG:
    succs = {off: successors(b.term) for off, b in fn.blocks.items()}
    # keep only edges that land on real blocks
    succs = {o: [s for s in ss if s in fn.blocks] for o, ss in succs.items()}
    preds: dict[int, list] = {o: [] for o in fn.blocks}
    for o, ss in succs.items():
        for s in ss:
            preds[s].append(o)

    idom = _dominators(fn.entry, succs, list(fn.blocks))
    dom = _dom_sets(idom, fn.entry)

    back_edges = []
    for a, ss in succs.items():
        for h in ss:
            if h in dom.get(a, set()):   # h dominates a  => a->h is a back edge
                back_edges.append((a, h))

    loops: dict[int, set] = {}
    for a, h in back_edges:
        loops.setdefault(h, set()).update(_natural_loop(a, h, preds))
    return CFG(entry=fn.entry, succs=succs, preds=preds, idom=idom,
               back_edges=back_edges, loops=loops)


def _rpo(entry: int, succs: dict[int, list]) -> list:
    seen, order = set(), []

    def dfs(n):
        seen.add(n)
        for s in succs.get(n, []):
            if s not in seen:
                dfs(s)
        order.append(n)

    dfs(entry)
    order.reverse()
    return order


def _dominators(entry: int, succs: dict[int, list], nodes: list) -> dict[int, int]:
    preds: dict[int, list] = {n: [] for n in nodes}
    for n, ss in succs.items():
        for s in ss:
            preds[s].append(n)
    order = _rpo(entry, succs)
    rank = {n: i for i, n in enumerate(order)}
    idom: dict[int, int] = {entry: entry}

    def intersect(a, b):
        while a != b:
            while rank[a] > rank[b]:
                a = idom[a]
            while rank[b] > rank[a]:
                b = idom[b]
        return a

    changed = True
    while changed:
        changed = False
        for n in order:
            if n == entry:
                continue
            new_idom = None
            for p in preds[n]:
                if p in idom:
                    new_idom = p if new_idom is None else intersect(p, new_idom)
            if new_idom is not None and idom.get(n) != new_idom:
                idom[n] = new_idom
                changed = True
    return idom


def _dom_sets(idom: dict[int, int], entry: int) -> dict[int, set]:
    dom: dict[int, set] = {}
    for n in idom:
        s, cur = {n}, n
        while cur != entry:
            cur = idom[cur]
            s.add(cur)
        dom[n] = s
    return dom


def _natural_loop(tail: int, header: int, preds: dict[int, list]) -> set:
    body = {header, tail}
    stack = [tail]
    while stack:
        n = stack.pop()
        for p in preds.get(n, []):
            if p not in body:
                body.add(p)
                stack.append(p)
    return body
