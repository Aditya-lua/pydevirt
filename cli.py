"""pydevirt command-line interface.

Commands:
  triage FILE       classify a protected sample (static, no exec)
  locate FILE       show the recovered VM structure + evidence
  opmap FILE        print the recovered opcode -> semantics map
  decode FILE       disassemble the (decoded) VM instruction stream
  decompile FILE    emit recovered Python source
  all FILE          triage + locate + opmap + decompile
  selftest          run the toy-VM corpus through the full pipeline + verify
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pipeline import devirtualize
from triage import triage_file
from vm.locate import locate


def _read(path: str) -> str:
    return Path(path).read_text()


def cmd_triage(args) -> int:
    res = triage_file(args.file)
    print(f"{res.path}: {res.classification.value}")
    for s in sorted(res.signals, key=lambda s: s.weight, reverse=True)[:12]:
        print(f"  [{s.weight:.1f}] {s.name}: {s.detail}")
    return 0


def cmd_locate(args) -> int:
    m = locate(_read(args.file))
    for e in m.evidence:
        print(" -", e)
    return 0


def cmd_opmap(args) -> int:
    rec = devirtualize(_read(args.file))
    for op in sorted(rec.opmap):
        info = rec.opmap[op]
        print(f"  0x{op:02x} ({op:>3}) -> {info.op.value:<14} conf={info.confidence:.2f}  {info.evidence}")
    return 0


def cmd_decode(args) -> int:
    rec = devirtualize(_read(args.file))
    for ins in rec.decoded.instrs:
        sem = rec.opmap[ins.op].op.value
        print(f"  {ins.offset:4d}: {sem:<14} op={ins.op:<3} operands={ins.operands}")
    for n in rec.decoded.notes:
        print("  note:", n)
    return 0


def cmd_decompile(args) -> int:
    rec = devirtualize(_read(args.file))
    print(rec.source)
    return 0


def cmd_all(args) -> int:
    cmd_triage(args); print()
    cmd_locate(args); print()
    cmd_opmap(args); print()
    print("# --- recovered source ---")
    cmd_decompile(args)
    return 0


def cmd_selftest(args) -> int:
    from corpus.programs import SAMPLES
    from corpus.toyvm.protect import emit_module
    from verify.diffexec import differential

    passed = 0
    for s in SAMPLES:
        orig = emit_module(s.assembled())
        try:
            rec = devirtualize(orig)
            rep = differential(orig, rec.source, s.inputs, name=s.name)
            status = "PASS" if rep.ok else "FAIL"
            passed += rep.ok
            extra = "" if rep.ok else f"  {rep.divergences[:1]}"
        except Exception as exc:  # noqa: BLE001
            status, extra = "ERR ", f"  {type(exc).__name__}: {exc}"
        print(f"  {s.name:<12} {status}{extra}")
    print(f"\n{passed}/{len(SAMPLES)} samples verified equivalent")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pydevirt", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in [("triage", cmd_triage), ("locate", cmd_locate), ("opmap", cmd_opmap),
                     ("decode", cmd_decode), ("decompile", cmd_decompile), ("all", cmd_all)]:
        p = sub.add_parser(name)
        p.add_argument("file")
        p.set_defaults(func=fn)
    sub.add_parser("selftest").set_defaults(func=cmd_selftest)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
