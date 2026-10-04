"""Unit tests for core.sandbox.

Covers: normal return, mutation capture, exception reporting, stdout capture,
wall-clock timeout kill, and network denial.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.sandbox import SandboxPolicy, run_function, run_source  # noqa: E402

ADD = "def f(a, b):\n    return a + b\n"
MUT = "def f(lst):\n    lst.append(99)\n    return len(lst)\n"
BOOM = "def f():\n    raise ValueError('nope')\n"
LOUD = "def f():\n    print('hello from sandbox')\n    return 1\n"
SPIN = "def f():\n    while True:\n        pass\n"
NET = "def f():\n    import socket\n    socket.socket()\n    return 'connected'\n"


def test_return():
    r = run_function(source=ADD, func="f", args=(2, 3))
    assert r.ok and r.returned == 5, r


def test_mutation_capture():
    r = run_function(source=MUT, func="f", args=([1, 2],))
    assert r.ok and r.returned == 3
    assert 0 in r.mutations, r.mutations


def test_exception_reported():
    r = run_function(source=BOOM, func="f")
    assert r.ok and r.exc_type == "ValueError", r
    assert "nope" in (r.exc_repr or "")


def test_stdout_capture():
    r = run_function(source=LOUD, func="f")
    assert r.ok and r.returned == 1
    assert "hello from sandbox" in r.stdout


def test_timeout_kills():
    r = run_function(source=SPIN, func="f", policy=SandboxPolicy(timeout=1.0, cpu_seconds=1))
    assert r.timed_out or r.killed, r
    assert not (r.ok and r.returned is not None)


def test_network_denied():
    r = run_function(source=NET, func="f")
    # the import+connect should raise OSError inside the sandbox
    assert r.exc_type in ("OSError", "error"), r
    assert r.returned != "connected"


def test_module_level_source():
    r = run_source("print('top-level')\nx = 40 + 2\n")
    assert r.ok and "top-level" in r.stdout


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print(f"ok  {name}")
    print("all sandbox tests passed")
