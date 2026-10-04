"""pydevirt.pipeline — glue the stages into one call.

locate -> decode -> semantics -> lift -> cfg -> structure/emit, returning the
recovered source plus the artifacts (opcode map, decoded listing, evidence) the
CLI and tests want.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from backend.pyemit import decompile
from ir.cfg import build_cfg
from ir.lift import lift
from vm.decode import disassemble
from vm.locate import locate
from vm.semantics import recover_semantics


@dataclass
class Recovered:
    source: str
    opmap: dict               # opcode int -> SemInfo
    decoded: object           # Decoded
    model: object             # VMModel
    evidence: list = field(default_factory=list)
    unrecovered: list = field(default_factory=list)


def devirtualize(module_src: str, func_name: str = "run") -> Recovered:
    model = locate(module_src)
    decoded = disassemble(model)
    opmap = recover_semantics(model)
    fn = lift(decoded, opmap, decoded.const_values, model.nlocals, name=func_name)
    cfg = build_cfg(fn)
    source = decompile(fn, cfg)
    return Recovered(source=source, opmap=opmap, decoded=decoded, model=model,
                     evidence=model.evidence, unrecovered=fn.unrecovered)
