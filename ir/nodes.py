"""pydevirt.ir.nodes — typed, stack-free IR.

Expressions are pure trees; statements have effects; each basic block ends in a
terminator that names successor *byte offsets* in the decoded VM stream. The
lifter produces these by simulating the VM stack symbolically, so nothing here
mentions a stack.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Union

# ---- expressions ---------------------------------------------------------- #


@dataclass(frozen=True)
class Const:
    value: object


@dataclass(frozen=True)
class Name:
    id: str


@dataclass(frozen=True)
class BinOp:
    op: str          # '+', '-', '*', '//', '%'
    left: "Expr"
    right: "Expr"


@dataclass(frozen=True)
class UnOp:
    op: str          # 'neg', 'not'
    operand: "Expr"


@dataclass(frozen=True)
class Compare:
    op: str          # '<', '<=', '>', '>=', '==', '!='
    left: "Expr"
    right: "Expr"


@dataclass(frozen=True)
class Call:
    func: str
    args: tuple      # tuple[Expr, ...]


@dataclass(frozen=True)
class Subscript:
    value: "Expr"
    index: "Expr"


@dataclass(frozen=True)
class ListLit:
    elts: tuple      # tuple[Expr, ...]


@dataclass(frozen=True)
class IterNext:
    """A value pulled from an iterator Name (the FOR_ITER per-iteration value)."""
    iterator: str


Expr = Union[Const, Name, BinOp, UnOp, Compare, Call, Subscript, ListLit, IterNext]

# ---- statements ----------------------------------------------------------- #


@dataclass
class Assign:
    target: str
    value: Expr


@dataclass
class Print:
    value: Expr


Stmt = Union[Assign, Print]

# ---- terminators (name successor byte offsets) ---------------------------- #


@dataclass
class Goto:
    target: int


@dataclass
class Branch:
    cond: Expr
    true_target: int    # taken when cond is truthy
    false_target: int


@dataclass
class Return:
    value: Expr


@dataclass
class ForIter:
    """Loop-top on an iterator: pull next into ``var`` and go to ``body``, or
    exhaust and go to ``exit_``."""
    iterator: str
    var: str
    body: int
    exit_: int


Terminator = Union[Goto, Branch, Return, ForIter]


@dataclass
class Block:
    offset: int
    stmts: list = field(default_factory=list)       # list[Stmt]
    term: Optional[Terminator] = None


@dataclass
class IRFunction:
    name: str
    params: list              # list[str]
    blocks: dict              # dict[int, Block], keyed by byte offset
    entry: int
    unrecovered: list = field(default_factory=list)  # notes for # UNRECOVERED
