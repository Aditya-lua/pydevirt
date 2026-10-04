"""Minimal unit tests for pydevirt.triage.

Run: python -m pytest pydevirt/tests/test_triage.py   (or: python tests/test_triage.py)
These build tiny synthetic samples for each family and assert the verdict.
"""

from __future__ import annotations

import importlib.util
import marshal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from triage import Family, triage_bytes  # noqa: E402


CUSTOM_VM_SRC = '''
def run(bytecode, consts):
    stack = []
    pc = 0
    while True:
        op = bytecode[pc]
        if op == 0:
            stack.append(consts[bytecode[pc + 1]]); pc += 2
        elif op == 1:
            b = stack.pop(); a = stack.pop(); stack.append(a + b); pc += 1
        elif op == 2:
            b = stack.pop(); a = stack.pop(); stack.append(a - b); pc += 1
        elif op == 3:
            b = stack.pop(); a = stack.pop(); stack.append(a * b); pc += 1
        elif op == 4:
            pc = bytecode[pc + 1]
        elif op == 5:
            if not stack.pop(): pc = bytecode[pc + 1]
            else: pc += 2
        elif op == 6:
            return stack.pop()
        else:
            raise RuntimeError(op)
'''

PACKER_SRC = '''
import base64, zlib, marshal
exec(marshal.loads(zlib.decompress(base64.b64decode(b"eJxyeJz..."))))
'''

PYARMOR_SRC = '''
from pytransform import pyarmor_runtime
pyarmor_runtime()
__pyarmor__(__name__, __file__, b"\\x00\\x01")
'''

PLAIN_SRC = '''
def add(a, b):
    return a + b
'''


def test_custom_vm():
    res = triage_bytes(CUSTOM_VM_SRC.encode())
    assert res.classification == Family.CUSTOM_VM, res.scores


def test_packer():
    res = triage_bytes(PACKER_SRC.encode())
    assert res.classification == Family.PACKER, res.scores


def test_native_vm():
    res = triage_bytes(PYARMOR_SRC.encode())
    assert res.classification == Family.NATIVE_VM, res.scores


def test_plain_source_is_not_vm():
    res = triage_bytes(PLAIN_SRC.encode())
    assert res.classification in (Family.BYTECODE_OBF, Family.UNKNOWN), res.scores


def test_pyc_roundtrip():
    # compile a packer-ish module and marshal it behind a realistic header
    code = compile(PACKER_SRC, "<pkg>", "exec")
    header = importlib.util.MAGIC_NUMBER + bytes(12)  # 3.7+ 16-byte header
    blob = header + marshal.dumps(code)
    res = triage_bytes(blob)
    assert res.kind == "pyc"
    assert res.classification in (Family.PACKER, Family.MIXED), res.scores


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all triage tests passed")
