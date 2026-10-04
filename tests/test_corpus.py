"""Validate the toy-VM corpus is correct ground truth.

For every sample: assemble it, run it (a) directly via the interpreter and
(b) through the emitted standalone protected module inside the sandbox, and
compare both to the reference oracle over all test inputs. Also assert triage
classifies the protected module as a custom VM (family C).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from corpus.programs import SAMPLES  # noqa: E402
from corpus.toyvm.interp import run_program  # noqa: E402
from corpus.toyvm.protect import emit_module  # noqa: E402
from core.sandbox import SandboxPolicy, run_function  # noqa: E402
from triage import Family, triage_bytes  # noqa: E402


def test_direct_matches_reference():
    for s in SAMPLES:
        prog = s.assembled()
        for args in s.inputs:
            got = run_program(prog, args)
            want = s.reference(*args)
            assert got == want, f"{s.name}{args}: direct={got!r} want={want!r}"


def test_standalone_module_matches_reference():
    for s in SAMPLES:
        src = emit_module(s.assembled())
        for args in s.inputs:
            r = run_function(source=src, func="run", args=args,
                             policy=SandboxPolicy(timeout=5, cpu_seconds=5))
            assert r.ok, f"{s.name}{args}: sandbox error {r.error} / {r.stderr}"
            want = s.reference(*args)
            assert r.returned == want, f"{s.name}{args}: vm={r.returned!r} want={want!r}"


def test_triage_flags_custom_vm():
    for s in SAMPLES:
        src = emit_module(s.assembled())
        res = triage_bytes(src.encode(), f"<{s.name}>")
        assert res.classification == Family.CUSTOM_VM, (s.name, res.scores)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print(f"ok  {name}")
    print("all corpus tests passed")
