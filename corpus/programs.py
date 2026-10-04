"""Corpus sample programs: toy-VM assembly + a reference Python implementation
+ test inputs, for each. The reference is the oracle for differential checks.

Constructs covered so far: while-loops, if/else branches, the iterator protocol
(GET_ITER/FOR_ITER), indexing, builtin calls. Still to add (tracked in
docs/PROJECT_MEMORY.md): exceptions, closures, generators, comprehensions, plus
control-flow flattening and opaque-predicate variants.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .toyvm.encode import Program, assemble


@dataclass
class Sample:
    name: str
    program: list[tuple]
    consts: list[Any]
    nlocals: int
    reference: Callable[..., Any]
    inputs: list[tuple] = field(default_factory=list)

    def assembled(self, **kw) -> Program:
        return assemble(self.program, self.consts, self.nlocals, **kw)


# --- sum_to_n: sum of range(n) via explicit counter loop -------------------- #
_sum_to_n = Sample(
    name="sum_to_n",
    consts=[0, 1],
    nlocals=3,  # 0=n, 1=acc, 2=i
    program=[
        ("LOAD_CONST", 0), ("STORE_LOCAL", 1),
        ("LOAD_CONST", 0), ("STORE_LOCAL", 2),
        ("LABEL", "loop"),
        ("LOAD_LOCAL", 2), ("LOAD_LOCAL", 0), ("LT"), ("JUMP_IF_FALSE", "end"),
        ("LOAD_LOCAL", 1), ("LOAD_LOCAL", 2), ("ADD"), ("STORE_LOCAL", 1),
        ("LOAD_LOCAL", 2), ("LOAD_CONST", 1), ("ADD"), ("STORE_LOCAL", 2),
        ("JUMP", "loop"),
        ("LABEL", "end"),
        ("LOAD_LOCAL", 1), ("RETURN"),
    ],
    reference=lambda n: sum(range(n)),
    inputs=[(0,), (1,), (5,), (10,), (100,)],
)

# --- factorial: acc=1; i=1; while i<=n: acc*=i; i+=1 ------------------------ #
_factorial = Sample(
    name="factorial",
    consts=[1],
    nlocals=3,  # 0=n, 1=acc, 2=i
    program=[
        ("LOAD_CONST", 0), ("STORE_LOCAL", 1),
        ("LOAD_CONST", 0), ("STORE_LOCAL", 2),
        ("LABEL", "loop"),
        ("LOAD_LOCAL", 2), ("LOAD_LOCAL", 0), ("LE"), ("JUMP_IF_FALSE", "end"),
        ("LOAD_LOCAL", 1), ("LOAD_LOCAL", 2), ("MUL"), ("STORE_LOCAL", 1),
        ("LOAD_LOCAL", 2), ("LOAD_CONST", 0), ("ADD"), ("STORE_LOCAL", 2),
        ("JUMP", "loop"),
        ("LABEL", "end"),
        ("LOAD_LOCAL", 1), ("RETURN"),
    ],
    reference=lambda n: __import__("math").factorial(n),
    inputs=[(0,), (1,), (5,), (7,)],
)

# --- abs_val: if x<0 return -x else x --------------------------------------- #
_abs_val = Sample(
    name="abs_val",
    consts=[0],
    nlocals=1,
    program=[
        ("LOAD_LOCAL", 0), ("LOAD_CONST", 0), ("LT"), ("JUMP_IF_FALSE", "pos"),
        ("LOAD_LOCAL", 0), ("NEG"), ("RETURN"),
        ("LABEL", "pos"),
        ("LOAD_LOCAL", 0), ("RETURN"),
    ],
    reference=lambda x: abs(x),
    inputs=[(-5,), (0,), (7,), (-1,)],
)

# --- max_list: best=lst[0]; for x in lst: if x>best: best=x ----------------- #
_max_list = Sample(
    name="max_list",
    consts=[0],
    nlocals=3,  # 0=lst, 1=best, 2=x
    program=[
        ("LOAD_LOCAL", 0), ("LOAD_CONST", 0), ("INDEX"), ("STORE_LOCAL", 1),
        ("LOAD_LOCAL", 0), ("GET_ITER"),
        ("LABEL", "loop"),
        ("FOR_ITER", "end"),
        ("STORE_LOCAL", 2),
        ("LOAD_LOCAL", 2), ("LOAD_LOCAL", 1), ("GT"), ("JUMP_IF_FALSE", "skip"),
        ("LOAD_LOCAL", 2), ("STORE_LOCAL", 1),
        ("LABEL", "skip"),
        ("JUMP", "loop"),
        ("LABEL", "end"),
        ("LOAD_LOCAL", 1), ("RETURN"),
    ],
    reference=lambda lst: max(lst),
    inputs=[([3, 1, 4, 1, 5, 9, 2, 6],), ([-1, -7, -3],), ([42],)],
)

# --- count_evens: count x where x%2==0 -------------------------------------- #
_count_evens = Sample(
    name="count_evens",
    consts=[0, 2, 1],
    nlocals=3,  # 0=lst, 1=cnt, 2=x
    program=[
        ("LOAD_CONST", 0), ("STORE_LOCAL", 1),
        ("LOAD_LOCAL", 0), ("GET_ITER"),
        ("LABEL", "loop"),
        ("FOR_ITER", "end"),
        ("STORE_LOCAL", 2),
        ("LOAD_LOCAL", 2), ("LOAD_CONST", 1), ("MOD"),
        ("LOAD_CONST", 0), ("EQ"), ("JUMP_IF_FALSE", "skip"),
        ("LOAD_LOCAL", 1), ("LOAD_CONST", 2), ("ADD"), ("STORE_LOCAL", 1),
        ("LABEL", "skip"),
        ("JUMP", "loop"),
        ("LABEL", "end"),
        ("LOAD_LOCAL", 1), ("RETURN"),
    ],
    reference=lambda lst: sum(1 for x in lst if x % 2 == 0),
    inputs=[([1, 2, 3, 4, 5, 6],), ([],), ([2, 4, 6],), ([1, 3, 5],)],
)

# --- fib: iterative nth Fibonacci ------------------------------------------- #
_fib = Sample(
    name="fib",
    consts=[0, 1],
    nlocals=4,  # 0=n, 1=a, 2=b, 3=i
    program=[
        ("LOAD_CONST", 0), ("STORE_LOCAL", 1),
        ("LOAD_CONST", 1), ("STORE_LOCAL", 2),
        ("LOAD_CONST", 0), ("STORE_LOCAL", 3),
        ("LABEL", "loop"),
        ("LOAD_LOCAL", 3), ("LOAD_LOCAL", 0), ("LT"), ("JUMP_IF_FALSE", "end"),
        ("LOAD_LOCAL", 1), ("LOAD_LOCAL", 2), ("ADD"),   # a+b on stack
        ("LOAD_LOCAL", 2), ("STORE_LOCAL", 1),           # a = b
        ("STORE_LOCAL", 2),                               # b = a+b
        ("LOAD_LOCAL", 3), ("LOAD_CONST", 1), ("ADD"), ("STORE_LOCAL", 3),
        ("JUMP", "loop"),
        ("LABEL", "end"),
        ("LOAD_LOCAL", 1), ("RETURN"),
    ],
    reference=lambda n: _fib_ref(n),
    inputs=[(0,), (1,), (2,), (10,), (20,)],
)

# --- sum_squares: sum(i*i for i in range(n)) via range builtin + FOR_ITER --- #
_sum_squares = Sample(
    name="sum_squares",
    consts=[0],
    nlocals=3,  # 0=n, 1=acc, 2=x
    program=[
        ("LOAD_CONST", 0), ("STORE_LOCAL", 1),
        ("LOAD_LOCAL", 0), ("CALL_BUILTIN", 1, 1), ("GET_ITER"),  # range(n)
        ("LABEL", "loop"),
        ("FOR_ITER", "end"),
        ("STORE_LOCAL", 2),
        ("LOAD_LOCAL", 1), ("LOAD_LOCAL", 2), ("LOAD_LOCAL", 2), ("MUL"), ("ADD"),
        ("STORE_LOCAL", 1),
        ("JUMP", "loop"),
        ("LABEL", "end"),
        ("LOAD_LOCAL", 1), ("RETURN"),
    ],
    reference=lambda n: sum(i * i for i in range(n)),
    inputs=[(0,), (1,), (4,), (10,)],
)


def _fib_ref(n: int) -> int:
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a


SAMPLES: list[Sample] = [
    _sum_to_n, _factorial, _abs_val, _max_list, _count_evens, _fib, _sum_squares,
]


def by_name(name: str) -> Sample:
    for s in SAMPLES:
        if s.name == name:
            return s
    raise KeyError(name)
