"""pydevirt.verify.diffexec — prove recovered code matches the original.

Runs the original protected module and the recovered source side by side in the
sandbox over the same inputs, comparing return value, raised exception
(type + args repr), and stdout. Returns a structured report; a single mismatch
is a divergence, not a crash.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from core.sandbox import SandboxPolicy, run_function


@dataclass
class Divergence:
    inputs: tuple
    field: str          # 'return' | 'exception' | 'stdout' | 'harness'
    original: str
    recovered: str


@dataclass
class VerifyReport:
    name: str
    total: int = 0
    passed: int = 0
    divergences: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.total > 0 and self.passed == self.total

    def summary(self) -> str:
        head = f"{self.name}: {self.passed}/{self.total} inputs equivalent"
        if self.ok:
            return head + "  ✓"
        lines = [head + "  ✗"]
        for d in self.divergences[:10]:
            lines.append(f"  {d.inputs} [{d.field}] original={d.original} recovered={d.recovered}")
        return "\n".join(lines)


def _run(src: str, func: str, args: tuple, policy: SandboxPolicy):
    return run_function(source=src, func=func, args=args, policy=policy)


def differential(
    original_src: str, recovered_src: str, inputs: list,
    *, orig_func: str = "run", rec_func: str = "run",
    name: str = "function", policy: Optional[SandboxPolicy] = None,
) -> VerifyReport:
    pol = policy or SandboxPolicy(timeout=5, cpu_seconds=5)
    rep = VerifyReport(name=name)
    for args in inputs:
        rep.total += 1
        a = _run(original_src, orig_func, args, pol)
        b = _run(recovered_src, rec_func, args, pol)
        if a.error or b.error:
            rep.divergences.append(Divergence(args, "harness", a.error or "ok", b.error or "ok"))
            continue
        # exceptions
        if (a.exc_type is not None) or (b.exc_type is not None):
            if a.exc_type != b.exc_type:
                rep.divergences.append(Divergence(args, "exception", str(a.exc_type), str(b.exc_type)))
                continue
        else:
            if a.returned_repr != b.returned_repr:
                rep.divergences.append(Divergence(args, "return", a.returned_repr, b.returned_repr))
                continue
        if a.stdout != b.stdout:
            rep.divergences.append(Divergence(args, "stdout", repr(a.stdout), repr(b.stdout)))
            continue
        rep.passed += 1
    return rep
