"""pydevirt.triage — fingerprint a protected Python sample WITHOUT executing it.

This is the Phase-1 deliverable. It reads a ``.py`` (source) or ``.pyc``
(marshalled code object) blob, looks for the static signals a protector leaves
behind, and classifies the sample into one of five families:

    A  packer only          -> unwrap, then hand to a standard decompiler
    B  bytecode obfuscation  -> junk ops / opaque predicates on real CPython bc
    C  custom Python VM      -> a hand-rolled interpreter loop lives in the file
    D  native-runtime VM     -> PyArmor BCC / pytransform / .so decryption
    E  mixed                 -> more than one of the above

Everything here is static: we parse source with ``ast`` and parse ``.pyc`` with
``marshal``. We never ``exec``/``eval`` the sample, and we never rely on the
host interpreter's ``opcode`` table to reason about the *target's* semantics.
"""

from __future__ import annotations

import argparse
import ast
import json
import marshal
import struct
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import CodeType
from typing import Optional


class Family(str, Enum):
    PACKER = "A:packer"
    BYTECODE_OBF = "B:bytecode-obfuscation"
    CUSTOM_VM = "C:custom-python-vm"
    NATIVE_VM = "D:native-runtime-vm"
    MIXED = "E:mixed"
    UNKNOWN = "unknown"


@dataclass
class Signal:
    """One piece of evidence, with a weight and a human-readable location."""

    name: str
    weight: float
    detail: str

    def as_dict(self) -> dict:
        return {"name": self.name, "weight": self.weight, "detail": self.detail}


@dataclass
class TriageResult:
    path: str
    kind: str  # "source" | "pyc" | "marshal"
    python_version: Optional[str]
    classification: Family
    scores: dict[str, float]
    signals: list[Signal] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "kind": self.kind,
            "python_version": self.python_version,
            "classification": self.classification.value,
            "scores": self.scores,
            "signals": [s.as_dict() for s in self.signals],
            "notes": self.notes,
        }


# --------------------------------------------------------------------------- #
# .pyc header handling (per-version; we do NOT trust the host alone)
# --------------------------------------------------------------------------- #
# magic int (little-endian u16 before \r\n) -> (python version, header bytes)
# Header layout by era (PEP 552):
#   2.7 .. 3.2  : magic(4) + mtime(4)                      = 8
#   3.3 .. 3.6  : magic(4) + mtime(4) + source_size(4)     = 12
#   3.7+        : magic(4) + bitfield(4) + mtime(4) + size  = 16
_MAGIC_TABLE: dict[int, tuple[str, int]] = {
    62211: ("2.7", 8),
    3379: ("3.6", 12),
    3390: ("3.7", 16),
    3391: ("3.7", 16),
    3392: ("3.7", 16),
    3394: ("3.7", 16),
    3400: ("3.8", 16),
    3401: ("3.8", 16),
    3410: ("3.8", 16),
    3411: ("3.8", 16),
    3412: ("3.8", 16),
    3413: ("3.8", 16),
    3420: ("3.9", 16),
    3421: ("3.9", 16),
    3422: ("3.9", 16),
    3423: ("3.9", 16),
    3424: ("3.9", 16),
    3425: ("3.9", 16),
    3430: ("3.10", 16),
    3431: ("3.10", 16),
    3432: ("3.10", 16),
    3433: ("3.10", 16),
    3434: ("3.10", 16),
    3435: ("3.10", 16),
    3436: ("3.10", 16),
    3438: ("3.11", 16),
    3439: ("3.11", 16),
    3450: ("3.12", 16),
    3451: ("3.12", 16),
    3495: ("3.13", 16),
    3531: ("3.13", 16),
}


def _looks_like_pyc(blob: bytes) -> bool:
    return len(blob) >= 4 and blob[2:4] == b"\r\n"


def parse_pyc(blob: bytes) -> tuple[Optional[str], Optional[CodeType], list[str]]:
    """Return (version, code_object_or_None, notes).

    We try the header length the magic implies; if the magic is unknown we probe
    16/12/8 in turn. marshal.loads only reconstructs the data structure (a code
    object) — it does not run anything.
    """
    notes: list[str] = []
    magic = struct.unpack("<H", blob[0:2])[0]
    version, header = _MAGIC_TABLE.get(magic, (None, 0))
    candidate_headers = [header] if header else [16, 12, 8]
    if version is None:
        notes.append(f"unknown .pyc magic {magic}; probing header lengths")

    for hlen in candidate_headers:
        try:
            code = marshal.loads(blob[hlen:])
        except Exception as exc:  # noqa: BLE001 - probing is expected to fail
            notes.append(f"marshal failed at header={hlen}: {exc!r}")
            continue
        if isinstance(code, CodeType):
            return version, code, notes
        notes.append(f"header={hlen} yielded {type(code).__name__}, not code")
    return version, None, notes


# --------------------------------------------------------------------------- #
# Source-level (AST) signal extraction
# --------------------------------------------------------------------------- #
_PACKER_CALLS = {
    "b64decode", "b85decode", "a85decode", "decompress", "loads",
    "decompressobj", "unhexlify",
}
_DANGER_EXEC = {"exec", "eval"}


class _AstScanner(ast.NodeVisitor):
    def __init__(self) -> None:
        self.signals: list[Signal] = []
        self.imports: set[str] = set()
        self.exec_sites = 0
        self.compile_sites = 0
        self.code_ctor = 0
        self.has_pyarmor = False
        self.has_settrace = False
        self.has_gettrace = False
        self.has_inspect = False
        self.has_code_attr = False
        self.timing_calls = 0
        # VM-shape heuristics
        self.while_true_with_dispatch = 0
        self.dispatch_tables = 0
        self.stack_pop_append = 0

    # -- imports ---------------------------------------------------------- #
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.imports.add(a.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self.imports.add(node.module.split(".")[0])
        self.generic_visit(node)

    # -- names ------------------------------------------------------------ #
    def visit_Name(self, node: ast.Name) -> None:
        if node.id in ("__pyarmor__", "pytransform", "pyarmor"):
            self.has_pyarmor = True
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        attr = node.attr
        if attr == "settrace":
            self.has_settrace = True
        elif attr == "setprofile":
            self.has_settrace = True
        elif attr == "gettrace":
            self.has_gettrace = True
        elif attr in ("perf_counter", "process_time", "monotonic"):
            self.timing_calls += 1
        elif attr == "__code__":
            self.has_code_attr = True
        self.generic_visit(node)

    # -- calls ------------------------------------------------------------ #
    def visit_Call(self, node: ast.Call) -> None:
        fname = self._callee_name(node.func)
        if fname in _DANGER_EXEC:
            self.exec_sites += 1
        elif fname == "compile":
            self.compile_sites += 1
        elif fname in ("CodeType", "FunctionType"):
            self.code_ctor += 1
        elif fname in _PACKER_CALLS:
            self.signals.append(
                Signal("packer-call", 0.6, f"call to {fname}() @ line {node.lineno}")
            )
        if fname == "time" or fname == "perf_counter":
            self.timing_calls += 1
        self.generic_visit(node)

    @staticmethod
    def _callee_name(func: ast.expr) -> str:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return ""

    # -- VM-shape: while True with a big if/elif chain or dispatch index -- #
    def visit_While(self, node: ast.While) -> None:
        is_true = (
            isinstance(node.test, ast.Constant) and node.test.value is True
        ) or isinstance(node.test, ast.NameConstant if hasattr(ast, "NameConstant") else ast.Constant)
        if _is_constant_true(node.test):
            branches = _count_elif_chain(node.body)
            subscripts = _count_subscript_dispatch(node.body)
            if branches >= 6:
                self.while_true_with_dispatch += 1
                self.signals.append(
                    Signal(
                        "vm-dispatch-ifelif",
                        1.0,
                        f"while-True with {branches}-way if/elif @ line {node.lineno}",
                    )
                )
            if subscripts:
                self.dispatch_tables += 1
                self.signals.append(
                    Signal(
                        "vm-dispatch-table",
                        1.0,
                        f"while-True indexing a table @ line {node.lineno}",
                    )
                )
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        # handlers[op]() style dispatch table (list/dict of callables)
        self.generic_visit(node)


def _is_constant_true(test: ast.expr) -> bool:
    return isinstance(test, ast.Constant) and test.value is True


def _count_elif_chain(body: list[ast.stmt]) -> int:
    """Count the arms of the largest if/elif chain directly inside ``body``."""
    best = 0
    for stmt in body:
        if isinstance(stmt, ast.If):
            n = 1
            cur = stmt
            while cur.orelse and len(cur.orelse) == 1 and isinstance(cur.orelse[0], ast.If):
                n += 1
                cur = cur.orelse[0]
            best = max(best, n)
    return best


def _count_subscript_dispatch(body: list[ast.stmt]) -> int:
    """Count calls of the form ``something[expr](...)`` — a dispatch table."""
    hits = 0
    for stmt in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(stmt, ast.Call) and isinstance(stmt.func, ast.Subscript):
            hits += 1
    return hits


def scan_source(src: str) -> _AstScanner:
    tree = ast.parse(src)
    scanner = _AstScanner()
    scanner.visit(tree)
    # stack push/pop texture is cheap to grep for in source
    scanner.stack_pop_append = src.count(".append(") + src.count(".pop(")
    return scanner


# --------------------------------------------------------------------------- #
# Code-object signal extraction (for .pyc) — structural, version-agnostic
# --------------------------------------------------------------------------- #
def scan_code_object(code: CodeType) -> list[Signal]:
    signals: list[Signal] = []
    names = set(code.co_names)
    for marker in ("__pyarmor__", "pyarmor", "pytransform"):
        if marker in names:
            signals.append(Signal("pyarmor-name", 1.0, f"co_names contains {marker!r}"))
    for packer in ("marshal", "zlib", "lzma", "b64decode", "loads", "decompress"):
        if packer in names:
            signals.append(Signal("packer-name", 0.5, f"co_names contains {packer!r}"))
    for danger in ("exec", "eval", "compile"):
        if danger in names:
            signals.append(Signal("exec-name", 0.5, f"co_names contains {danger!r}"))

    # nested code objects + large bytes/str constant => embedded payload
    nested = sum(1 for c in code.co_consts if isinstance(c, CodeType))
    big_blobs = [c for c in code.co_consts if isinstance(c, (bytes, str)) and len(c) > 512]
    if big_blobs:
        signals.append(
            Signal("embedded-blob", 0.7, f"{len(big_blobs)} const blob(s) > 512 bytes")
        )
    if nested == 0 and big_blobs:
        signals.append(
            Signal("no-nested-code", 0.4, "payload present but no nested code objects (packed?)")
        )
    return signals


# --------------------------------------------------------------------------- #
# Scoring & classification
# --------------------------------------------------------------------------- #
def classify(scanner: Optional[_AstScanner], code_signals: list[Signal]) -> tuple[Family, dict[str, float], list[Signal]]:
    scores = {f.value: 0.0 for f in (Family.PACKER, Family.BYTECODE_OBF, Family.CUSTOM_VM, Family.NATIVE_VM)}
    evidence: list[Signal] = list(code_signals)

    for s in code_signals:
        if s.name == "pyarmor-name":
            scores[Family.NATIVE_VM.value] += s.weight
        elif s.name in ("packer-name", "exec-name", "embedded-blob", "no-nested-code"):
            scores[Family.PACKER.value] += s.weight

    if scanner is not None:
        evidence.extend(scanner.signals)
        if scanner.has_pyarmor:
            scores[Family.NATIVE_VM.value] += 2.0
            evidence.append(Signal("pyarmor", 2.0, "pyarmor/pytransform symbol in source"))

        packer_chain = scanner.exec_sites and (
            "marshal" in scanner.imports or "zlib" in scanner.imports or "base64" in scanner.imports
        )
        if packer_chain:
            scores[Family.PACKER.value] += 1.5
            evidence.append(Signal("exec-packer-chain", 1.5,
                                   f"{scanner.exec_sites} exec/eval site(s) + packer imports"))
        if scanner.code_ctor:
            scores[Family.PACKER.value] += 0.8
            evidence.append(Signal("code-ctor", 0.8,
                                   f"{scanner.code_ctor} CodeType/FunctionType construction(s)"))

        # custom VM shape
        vm_score = (
            scanner.while_true_with_dispatch * 1.5
            + scanner.dispatch_tables * 1.5
            + (0.5 if scanner.stack_pop_append >= 4 else 0.0)
        )
        scores[Family.CUSTOM_VM.value] += vm_score
        if scanner.stack_pop_append >= 4:
            evidence.append(Signal("stack-texture", 0.5,
                                   f"{scanner.stack_pop_append} append/pop sites (VM stack?)"))

        # anti-analysis (not a family on its own, but raises VM/native suspicion)
        if scanner.has_settrace or scanner.has_gettrace:
            evidence.append(Signal("trace-hook", 0.5, "sys.settrace/gettrace present"))
            scores[Family.CUSTOM_VM.value] += 0.3
        if scanner.timing_calls:
            evidence.append(Signal("timing-check", 0.3, f"{scanner.timing_calls} timing call(s)"))
        if scanner.has_code_attr:
            evidence.append(Signal("code-integrity", 0.3, "__code__ access (integrity check?)"))

    # bytecode-obfuscation (B) is mostly a residual: a .pyc with real code but
    # no VM/packer/native signal, OR source that compiles to junk — we flag it
    # weakly so it surfaces when nothing else does.
    if not any(scores.values()):
        scores[Family.BYTECODE_OBF.value] += 0.5

    # pick winners; declare MIXED when two families are both strong
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    top_val = ranked[0][1]
    strong = [k for k, v in ranked if v >= 1.0 and v >= 0.6 * top_val]
    if top_val == 0.0:
        return Family.UNKNOWN, scores, evidence
    if len(strong) >= 2:
        return Family.MIXED, scores, evidence
    return Family(ranked[0][0]), scores, evidence


# --------------------------------------------------------------------------- #
# Top-level driver
# --------------------------------------------------------------------------- #
def triage_bytes(blob: bytes, path: str = "<memory>") -> TriageResult:
    if _looks_like_pyc(blob):
        version, code, notes = parse_pyc(blob)
        code_signals: list[Signal] = []
        if code is not None:
            code_signals = scan_code_object(code)
        family, scores, evidence = classify(None, code_signals)
        return TriageResult(path, "pyc", version, family, scores, evidence, notes)

    # treat as source text
    text = blob.decode("utf-8", errors="replace")
    notes = []
    try:
        scanner = scan_source(text)
    except SyntaxError as exc:
        notes.append(f"source did not parse: {exc!r}")
        scanner = None
    family, scores, evidence = classify(scanner, [])
    return TriageResult(path, "source", None, family, scores, evidence, notes)


def triage_file(path: str | Path) -> TriageResult:
    p = Path(path)
    res = triage_bytes(p.read_bytes(), str(p))
    return res


def _main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Fingerprint a protected Python sample (static, no exec).")
    ap.add_argument("path", help=".py or .pyc file to triage")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args(argv)

    res = triage_file(args.path)
    if args.json:
        print(json.dumps(res.as_dict(), indent=2))
        return 0

    print(f"sample     : {res.path}")
    print(f"kind       : {res.kind}")
    print(f"py version : {res.python_version or 'unknown'}")
    print(f"verdict    : {res.classification.value}")
    print("scores     :")
    for fam, val in sorted(res.scores.items(), key=lambda kv: kv[1], reverse=True):
        print(f"   {fam:<28} {val:.2f}")
    print("evidence   :")
    for s in sorted(res.signals, key=lambda s: s.weight, reverse=True):
        print(f"   [{s.weight:.1f}] {s.name}: {s.detail}")
    for n in res.notes:
        print(f"note       : {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
