# pydevirt

A modular, **generalizing** devirtualizer for VM-protected Python. Given an
obfuscated sample, it discovers the protection's structure (never hardcodes
per-sample facts), recovers an opcode→semantics map, lifts each protected
function to a stack-free IR, emits readable Python, and proves equivalence by
differential execution.

> Authorized security research / malware analysis / CTF / interoperability only.
> Analyze code you own or are permitted to study.

## Why "generalizing"

Per-sample facts (opcode numbers, key schedules, const-pool layout) are
**discovered** at analysis time and cached as JSON profiles under `profiles/`.
Hardcoding one sample's opcode table is treated as a failure.

## Protection families (triage)

| Class | Meaning | Strategy |
|-------|---------|----------|
| **A** | Packer only (`exec(marshal.loads(zlib.decompress(...)))`) | peel layers, hand to a standard decompiler |
| **B** | CPython bytecode obfuscation (junk ops, opaque predicates) | decode with per-version tables, run IR cleanup, re-emit |
| **C** | Custom Python VM (hand-rolled interpreter loop) | **primary target** — locate loop, recover opcodes, lift, structure, emit |
| **D** | Native-runtime VM (PyArmor BCC / `.so`) | capture plaintext code objects at CPython chokepoints (PEP 523 / 578, `marshal.loads`) |
| **E** | Mixed | peel outer layer, re-triage, recurse |

## Status

Built phase by phase (design-gated). Shipped so far:

- [x] **Phase 0** — requirements, defaults
- [x] **Phase 1** — triage & threat model + `triage.py` (static, no-exec fingerprinter)
- [x] **Phase 2** — architecture (see `docs/ARCHITECTURE.md`)
- [ ] **Phase 3/4** — core + VM + IR + backend implementation
- [ ] **Phase 5** — differential-execution verification + toy-VM corpus
- [ ] **Phase 6** — optimization & anti-analysis hardening review

## Layout (target)

```
pydevirt/
  core/      loader, unpack, sandbox, tracer
  vm/        locate, handlers, semantics, opmap, decode
  ir/        nodes, lift, cfg, ssa, passes/
  backend/   structurer, pyemit, bcemit
  verify/    diffexec, fuzz, report
  profiles/  cached per-protector opcode maps (JSON)
  cli.py     triage | unpack | locate | opmap | lift | decompile | verify | all
  tests/
```

## Quick start

```bash
python triage.py path/to/sample.py          # human-readable verdict + evidence
python triage.py path/to/sample.pyc --json   # machine-readable
python -m pytest                             # run tests
```

## Safety

Dynamic analysis runs only in an isolated subprocess (resource limits, no
network, patched builtins, timeout). A Python-level sandbox is **not** a
security boundary — run real untrusted samples inside a container or VM.

## Support / Donate

<div align="center">
  <img src="assets/donate/donate_header.png" width="520" alt="Buy me a coffee — fund future projects">
</div>

If these tools are useful to you, you can help fund future projects by sending
crypto to the addresses below. Thank you for the support. — **@adi.codz** (Discord)

| Network | Address | Scan |
|---|---|---|
| **Bitcoin** (BTC) | `bc1q3nprh6e0y4fz88ft4uu5dad7xsx629z498dkay` | <img src="assets/donate/btc.png" width="120" alt="Bitcoin QR"> |
| **Ethereum** (ERC-20) | `0x11369a1d18eb442581D1e675dAdD94eBA1c4bE52` | <img src="assets/donate/eth.png" width="120" alt="Ethereum QR"> |
| **BNB Smart Chain** (BEP-20) | `0x11369a1d18eb442581D1e675dAdD94eBA1c4bE52` | <img src="assets/donate/bnb.png" width="120" alt="BNB Smart Chain QR"> |
| **Solana** (SOL) | `AVKBDNT2PzYDJ7njVrjt7MoVZ1tY4DvNSsADdujiGKTC` | <img src="assets/donate/sol.png" width="120" alt="Solana QR"> |
| **Litecoin** (LTC) | `ltc1qu4ahsjff622xqjlqwafhlgmacd5ea477sqpx9z` | <img src="assets/donate/ltc.png" width="120" alt="Litecoin QR"> |

> Send each asset only on its own network. ETH and BNB share one EVM address —
> use it for ERC-20 on Ethereum and BEP-20 on BNB Smart Chain. Assets sent on the
> wrong network may be lost.
