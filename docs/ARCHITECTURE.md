# pydevirt architecture

```
  sample (.py/.pyc) ─▶ core/loader ─▶ core/unpack ─▶ [triage routing]
                                                         │
                             class C/E ───────────────────┘
   vm/locate ─▶ VMModel(loop, dispatch, blob, constpool, keyschedule, stack, pc)
       │  evidence-scored candidates, confirmed by core/tracer (dynamic)
       ▼
   vm/handlers ─▶ [HandlerUnit]        vm/decode ─▶ [VMInstr] (operands, jumps)
       ▼                                     ▲  key schedule recovered by trace
   vm/semantics (static+symbolic+concrete) ──┘
       ▼
   vm/opmap ─▶ OpMap{opcode→SemOp, confidence, evidence}  ⇄  profiles/*.json
       ▼
   ir/lift (stack sim → 3-addr) ─▶ ir/cfg ─▶ ir/ssa ─▶ ir/passes/*
       ▼
   backend/structurer ─▶ backend/pyemit  (└▶ backend/bcemit fallback)
       ▼
   verify/diffexec + verify/fuzz ─▶ verify/report
```

`core/sandbox` backs every dynamic step (tracer, semantics probing, verify):
subprocess, resource limits, no network, patched builtins, timeout.

## Module contracts

| Module | Responsibility | In → Out | Key failure modes |
|--------|----------------|----------|-------------------|
| core/loader | read `.py`/`.pyc`/marshal; per-version header | `Path/bytes → CodeBlob` | unknown magic, truncated marshal |
| core/unpack | peel b64/zlib/lzma/xor/marshal/exec | `CodeBlob → UnpackedUnit{payload, layers[]}` | unknown codec, non-terminating chain |
| core/sandbox | isolated exec for all dynamic work | `(code, inputs) → RunResult` | timeout, OOM, escape attempt |
| core/tracer | concrete/opcode trace + dispatch instrumentation | `(unit, inputs) → Trace` | sample refuses, trace-hook detection |
| vm/locate | score + confirm dispatch loop/table/blob/pc/stack | `UnpackedUnit → VMModel` | no candidate, multiple loops |
| vm/handlers | slice each handler into an analyzable unit | `VMModel → [HandlerUnit]` | inlined/shared handlers |
| vm/semantics | classify via static+symbolic+concrete, fused | `HandlerUnit → SemOp{op,conf,evidence}` | polymorphic/split handlers |
| vm/opmap | opcode→SemOp map; (de)serialize profiles | `[SemOp] → OpMap` ⇄ JSON | conflicting evidence |
| vm/decode | operand widths, rolling/XOR keys, jump kind | `(VMModel, blob) → [VMInstr]` | wrong key schedule |
| ir/lift | simulate VM stack → 3-addr IR; exception edges | `[VMInstr]+OpMap → IRFunction` | unbalanced stack at merge |
| ir/cfg | blocks, dominators, loops | `IRFunction → CFG` | irreducible CFG |
| ir/ssa | SSA build/destroy (optional) | `CFG → SSA` | — |
| ir/passes/* | fold, copy-prop, DCE, opaque-pred, deflatten, MBA | `IR → IR` | over-eager removal (verify guards) |
| backend/structurer | dom-based → structured control flow, no goto | `CFG → StructuredAST` | residual goto |
| backend/pyemit | IR→`ast`→source; `compile()` sanity; naming | `StructuredAST → str` | unparseable node |
| backend/bcemit | IR→real code object (decompiler fallback) | `IRFunction → CodeType` | version mismatch |
| verify/* | differential exec, fuzzing, report | `(orig, recovered) → Report` | flaky I/O |

## Load-bearing decisions (and rejected alternatives)

1. **Discover-then-cache profiles; zero hardcoded opcodes.** Rejected: per-sample constants (fails generalization).
2. **Three fused semantic signals (static + symbolic + concrete).** Rejected: pattern-only (breaks on renaming) or concrete-only (misses rare branches).
3. **Stack-free three-address IR as the single hub.** Rejected: decompiling VM dispatch directly. One IR serves both B and C.
4. **Dynamic work only in a subprocess sandbox.** Rejected: in-process `exec`. A Python sandbox is not a boundary — use a container/VM.
5. **Native-VM (D) = runtime capture, not native devirt.** Capture plaintext code objects at CPython chokepoints; never invent PyArmor internals.
6. **z3 optional, abstract interpretation first.** Rejected: hard z3 dependency.
7. **Graceful degradation over crashes.** Unrecoverable handlers emit `# UNRECOVERED: handler 0x.. @ pc 0x.. (evidence: ...)`.
