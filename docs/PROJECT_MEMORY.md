# Project Memory — pydevirt

_Maintained per Aditya's engineering workflow; update after each project-related change._

## Goals
- A modular, **generalizing** devirtualizer for VM-protected Python.
- Discover per-sample facts (opcodes, keys, const pool) at analysis time; cache
  as JSON profiles. **Never hardcode** a sample's opcode numbers.
- Outputs: recovered opcode map (with confidence + evidence), lifted IR,
  readable Python source (or fallback CPython bytecode), and a differential
  equivalence report.
- Prove the pipeline end to end against a self-built toy VM — no dependency on
  any third-party sample.

## Features (target surface)
- `triage` — static, no-exec fingerprint → family A/B/C/D/E + evidence.
- `unpack` — peel b64/zlib/lzma/xor/marshal/exec layers.
- `locate` — find the VM dispatch loop / table / blob / pc / stack.
- `opmap` — opcode → semantics via fused static + symbolic + concrete signals.
- `lift` / `decompile` — VM instrs → 3-addr IR → structured Python.
- `verify` — differential execution in a sandbox + coverage report.

## Completed
- Phase 0 — requirements + defaults locked (3.11 primary, pure-Python VM focus,
  sandbox allowed, both source+IR output, z3 optional).
- Phase 1 — `triage.py`: static fingerprinter, per-version `.pyc` header table,
  weighted evidence, 5-family classifier. Unit tests 5/5 green.
- Phase 2 — architecture (`docs/ARCHITECTURE.md`): module graph, typed
  contracts, failure modes, 7 load-bearing decisions.
- Repo scaffold: README (+ Support/Donate), `.gitignore`, assets.

## Pending
- Phase 2 architecture sign-off from Aditya (GATE).
- Push to `Aditya-lua/pydevirt` once the remote repo exists.
- Phase 3/4 build (bottom-up): `core/loader` → `core/sandbox` → toy-VM corpus →
  `vm/*` → `ir/*` → `backend/*`, each with a unit test.
- Phase 5 verification; Phase 6 optimization + anti-analysis review.

## Bugs
- _(none open)_
- Fixed: test `.pyc` header literal was double-escaped (`b"\\x00"` = 4 bytes),
  making `marshal` read the wrong offset → `code=None`. Fix: build the 16-byte
  header with `bytes(12)`. Root cause was in the test, not `triage.py`.

## Decisions
- Project lives in its **own** repo (`Aditya-lua/pydevirt`), not inside the
  unrelated `Deobfuscator-Luraph-V15` repo.
- Stack-free three-address IR as the single hub for both bytecode-obfuscation
  (B) and custom-VM (C) paths.
- Native-runtime VMs (D) handled by **capturing** plaintext code objects at
  CPython chokepoints (PEP 523 frame-eval, PEP 578 audit hooks, `marshal.loads`),
  not by reversing native VM internals.
- All dynamic analysis runs only in an isolated subprocess; a Python sandbox is
  explicitly not treated as a security boundary.

## Change Log
- 2026-10-04 — Scaffolded repo; shipped Phase 0–2 (triage + architecture);
  added Support/Donate section and Project Memory. Committed as Aditya (one
  commit), pending remote creation + push.
