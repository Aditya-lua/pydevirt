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
  weighted evidence, 5-family classifier. 5/5 tests.
- Phase 2 — architecture (`docs/ARCHITECTURE.md`): module graph, typed
  contracts, failure modes, 7 load-bearing decisions. **Approved.**
- Repo scaffold: README (+ Support/Donate), `.gitignore`, assets. Pushed to
  `Aditya-lua/pydevirt` (main).
- Phase 4 foundation:
  - `core/loader.py` — typed blob reader, per-version `.pyc` headers (4/4).
  - `core/sandbox.py` — subprocess isolation: rlimits, timeout-kill, net/fs/
    subprocess deny shims, mutation capture (7/7).
  - `corpus/` toy VM — ISA (~28 ops), rolling-XOR encoder + encrypted const
    pool, canonical interpreter loop, standalone-module protector, 7 sample
    programs with reference oracles (3/3; all samples verified direct + in
    sandbox + triaged as custom-VM). **19/19 tests total.**

- Phase 4 vertical slice (depth-first): full pipeline on the toy VM.
  - `vm/locate` (dispatch fn, arms, names, decode exprs, data globals via
    wrapper call site), `vm/decode` (operand widths from arms, rolling-XOR
    replay, const decryption, linear disasm), `vm/semantics` (AST classifier →
    **29/29 opcodes recovered, full confidence** vs known ISA).
  - `ir/nodes`, `ir/lift` (symbolic stack sim → 3-addr IR, spill-before-store
    to fix the lost-copy hazard), `ir/cfg` (dominators, natural loops).
  - `backend/structurer` (post-dominator-guided while/if recovery),
    `backend/pyemit` (IR→ast→source + compile sanity).
  - `verify/diffexec` (differential execution in sandbox), `pipeline.py`, `cli.py`.
  - **7/7 corpus samples verified equivalent end-to-end** with clean readable
    source. For-loops handled via CFG-skeleton-first lifting + entry-stack
    propagation in RPO (the iterator is a loop-carried stack value); FOR_ITER's
    "var = next" store is folded into the `for` target by the structurer.

## Pending
- Corpus expansion: exceptions, closures, generators, comprehensions; plus
  control-flow flattening and opaque-predicate variants (Phase 5/6 needs).
- `ir/ssa`, `ir/passes/*` (const-fold, DCE, opaque-pred, deflatten), `backend/
  bcemit`, `verify/fuzz` + `verify/report`.
- Phase 6 optimization + anti-analysis review; honest known-limitations.

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
  added Support/Donate section and Project Memory. Pushed to main.
- 2026-10-04 — Phase 4 foundation: core/loader, core/sandbox, and the toy-VM
  corpus (ISA/encode/interp/protect + 7 programs). Suite at 19/19.
- 2026-10-04 — Phase 4 vertical slice: full locate→decode→semantics→lift→cfg→
  structure→emit→verify pipeline + CLI. 7/7 corpus samples recovered to
  readable Python and verified equivalent.
