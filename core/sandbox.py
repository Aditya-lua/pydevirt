"""pydevirt.core.sandbox — run sample / recovered code in isolation.

Every dynamic step (tracer, concrete handler probing, differential verification)
funnels through here. We **never** exec sample code in the analysis process:
each run is a fresh ``python3 -I -B`` subprocess in its own session and temp cwd,
with POSIX resource limits (CPU seconds, address space, file size, open files),
a wall-clock timeout enforced by killing the process *group*, and builtins that
deny network / filesystem / subprocess by default.

HONEST LIMITS: a Python-level sandbox is **not** a security boundary. ``ctypes``,
native modules, or a determined ``os``/``sys`` call can defeat the builtin
patches, and POSIX rlimits don't stop network egress. For genuinely untrusted
samples, run this whole tool inside a container or disposable VM. What this
buys you is protection against *accidental* damage and runaway resource use
during analysis, plus clean capture of effects.
"""

from __future__ import annotations

import base64
import os
import pickle
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

_RESULT_NAME = "__pydevirt_result.pkl"


@dataclass
class SandboxPolicy:
    timeout: float = 5.0          # wall-clock seconds
    cpu_seconds: int = 5          # RLIMIT_CPU hard backstop
    mem_mb: int = 512             # RLIMIT_AS
    fsize_mb: int = 16            # RLIMIT_FSIZE
    nofile: int = 64              # RLIMIT_NOFILE
    allow_net: bool = False
    allow_fs_write: bool = False
    allow_subprocess: bool = False


@dataclass
class RunResult:
    ok: bool = False                       # target ran to completion (no infra error)
    returned: Any = None
    returned_repr: str = ""
    exc_type: Optional[str] = None
    exc_repr: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    killed: bool = False
    returncode: Optional[int] = None
    mutations: dict[int, tuple[str, str]] = field(default_factory=dict)  # argidx -> (before, after)
    error: Optional[str] = None            # harness-level failure (not the target's)


# --------------------------------------------------------------------------- #
# Driver executed inside the subprocess. Kept dependency-free; talks pickle on
# fd 3. It re-applies rlimits itself (defense in depth) and installs the deny
# shims before any sample code runs.
# --------------------------------------------------------------------------- #
_DRIVER = textwrap.dedent(
    r'''
    import base64, io, os, pickle, sys
    from contextlib import redirect_stdout, redirect_stderr

    job = pickle.loads(base64.b64decode(sys.argv[1].encode()))
    _result_path = sys.argv[2]
    # open the result sink NOW, before any deny-shims or sample code run
    _result_fd = os.open(_result_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    pol = job["policy"]

    # --- resource limits (defense in depth; parent also sets preexec) -------
    try:
        import resource
        def _lim(res, soft):
            try:
                _, hard = resource.getrlimit(res)
                resource.setrlimit(res, (soft, hard if hard != resource.RLIM_INFINITY else soft))
            except Exception:
                pass
        _lim(resource.RLIMIT_CPU, pol["cpu_seconds"])
        _lim(resource.RLIMIT_AS, pol["mem_mb"] * 1024 * 1024)
        _lim(resource.RLIMIT_FSIZE, pol["fsize_mb"] * 1024 * 1024)
        _lim(resource.RLIMIT_NOFILE, pol["nofile"])
    except Exception:
        pass

    # --- deny shims ---------------------------------------------------------
    import builtins as _b
    if not pol["allow_net"]:
        try:
            import socket
            def _nonet(*a, **k): raise OSError("network disabled by sandbox")
            socket.socket = _nonet
            socket.create_connection = _nonet
        except Exception:
            pass
    if not pol["allow_subprocess"]:
        try:
            import subprocess as _sp
            def _nosp(*a, **k): raise OSError("subprocess disabled by sandbox")
            _sp.Popen = _nosp; _sp.run = _nosp; _sp.call = _nosp
        except Exception:
            pass
        os.system = lambda *a, **k: (_ for _ in ()).throw(OSError("os.system disabled"))
    if not pol["allow_fs_write"]:
        _real_open = _b.open
        def _ro_open(file, mode="r", *a, **k):
            if any(m in mode for m in ("w", "a", "x", "+")):
                raise OSError("filesystem writes disabled by sandbox")
            return _real_open(file, mode, *a, **k)
        _b.open = _ro_open

    # --- load + run ---------------------------------------------------------
    src = job["source"]; code = job["code"]
    func = job["func"]; args = job["args"]; kwargs = job["kwargs"]

    def _safe_repr(x):
        try: return repr(x)
        except Exception as e: return f"<unrepr {type(x).__name__}: {e}>"

    def _snapshot(x):
        try:
            import copy; return copy.deepcopy(x)
        except Exception:
            return _safe_repr(x)

    ns = {"__name__": "__sandbox__"}
    out, err = io.StringIO(), io.StringIO()
    result = {"ok": False}
    try:
        with redirect_stdout(out), redirect_stderr(err):
            if code is not None:
                import marshal
                exec(marshal.loads(code), ns)
            elif src is not None:
                exec(compile(src, "<sandbox>", "exec"), ns)
            if func is not None:
                target = ns[func]
                before = [_snapshot(a) for a in args]
                rv = target(*args, **dict(kwargs))
                muts = {}
                for i, (b, a) in enumerate(zip(before, args)):
                    try: changed = (b != a)
                    except Exception: changed = (_safe_repr(b) != _safe_repr(a))
                    if changed:
                        muts[i] = (_safe_repr(b), _safe_repr(a))
                result = {"ok": True, "returned": rv, "returned_repr": _safe_repr(rv),
                          "mutations": muts}
            else:
                result = {"ok": True, "returned": None, "returned_repr": "None",
                          "mutations": {}}
    except BaseException as exc:   # noqa: BLE001 — we are reporting the target's error
        result = {"ok": True, "exc_type": type(exc).__name__,
                  "exc_repr": _safe_repr(exc), "mutations": {}}
    finally:
        result["stdout"] = out.getvalue()
        result["stderr"] = err.getvalue()

    # pickle result to the pre-opened sink; fall back to repr-only if unpicklable
    try:
        payload = pickle.dumps(result)
    except Exception:
        result.pop("returned", None)
        payload = pickle.dumps(result)
    os.write(_result_fd, payload)
    os.close(_result_fd)
    '''
)


def _preexec(pol: SandboxPolicy):  # pragma: no cover - runs in child only
    import resource

    os.setsid()

    def lim(res, soft):
        try:
            _, hard = resource.getrlimit(res)
            hard = soft if hard == resource.RLIM_INFINITY else hard
            resource.setrlimit(res, (soft, hard))
        except Exception:
            pass

    lim(resource.RLIMIT_CPU, pol.cpu_seconds)
    lim(resource.RLIMIT_AS, pol.mem_mb * 1024 * 1024)
    lim(resource.RLIMIT_FSIZE, pol.fsize_mb * 1024 * 1024)
    lim(resource.RLIMIT_NOFILE, pol.nofile)


def run_function(
    *,
    source: Optional[str] = None,
    code_marshal: Optional[bytes] = None,
    func: Optional[str] = None,
    args: tuple = (),
    kwargs: Optional[dict] = None,
    policy: Optional[SandboxPolicy] = None,
) -> RunResult:
    """Exec ``source`` (or a marshalled code object), optionally call ``func``.

    Exactly one of ``source`` / ``code_marshal`` should be given. Returns a
    :class:`RunResult`; infra failures (timeout, kill, unpicklable job) set
    ``error``/``timed_out``/``killed`` rather than raising.
    """
    pol = policy or SandboxPolicy()
    if (source is None) == (code_marshal is None):
        return RunResult(error="exactly one of source/code_marshal required")

    job = {
        "source": source,
        "code": code_marshal,
        "func": func,
        "args": args,
        "kwargs": tuple((kwargs or {}).items()),
        "policy": {
            "cpu_seconds": pol.cpu_seconds, "mem_mb": pol.mem_mb,
            "fsize_mb": pol.fsize_mb, "nofile": pol.nofile,
            "allow_net": pol.allow_net, "allow_fs_write": pol.allow_fs_write,
            "allow_subprocess": pol.allow_subprocess,
        },
    }
    try:
        arg_b64 = base64.b64encode(pickle.dumps(job)).decode()
    except Exception as exc:  # noqa: BLE001
        return RunResult(error=f"job not picklable: {exc!r}")

    with tempfile.TemporaryDirectory(prefix="pydevirt-sbx-") as td:
        driver = Path(td) / "driver.py"
        driver.write_text(_DRIVER)
        result_path = Path(td) / _RESULT_NAME
        try:
            proc = subprocess.Popen(
                [sys.executable, "-I", "-B", str(driver), arg_b64, str(result_path)],
                cwd=td,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=(lambda: _preexec(pol)) if os.name == "posix" else None,
            )
        except Exception as exc:  # noqa: BLE001
            return RunResult(error=f"spawn failed: {exc!r}")

        timed_out = False
        try:
            cap_out, cap_err = proc.communicate(timeout=pol.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(proc)
            cap_out, cap_err = proc.communicate()

        payload = result_path.read_bytes() if result_path.exists() else b""

    res = _decode(payload)
    res.stdout = res.stdout or _safe_decode(cap_out)
    res.stderr = res.stderr or _safe_decode(cap_err)
    res.returncode = proc.returncode
    res.timed_out = timed_out
    if timed_out:
        res.killed = True
        res.error = res.error or "wall-clock timeout"
    elif payload == b"" and not res.ok:
        res.killed = True
        res.error = res.error or f"no result (rc={proc.returncode}); likely rlimit kill"
    return res


def run_source(source: str, *, policy: Optional[SandboxPolicy] = None) -> RunResult:
    """Convenience: exec module-level ``source`` and capture stdout/effects."""
    return run_function(source=source, func=None, policy=policy)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _kill_group(proc: subprocess.Popen) -> None:
    import signal
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _safe_decode(b: Optional[bytes]) -> str:
    return b.decode("utf-8", "replace") if b else ""


def _decode(payload: bytes) -> RunResult:
    if not payload:
        return RunResult(ok=False)
    try:
        d = pickle.loads(payload)
    except Exception as exc:  # noqa: BLE001
        return RunResult(ok=False, error=f"result decode failed: {exc!r}")
    return RunResult(
        ok=d.get("ok", False),
        returned=d.get("returned"),
        returned_repr=d.get("returned_repr", ""),
        exc_type=d.get("exc_type"),
        exc_repr=d.get("exc_repr"),
        stdout=d.get("stdout", ""),
        stderr=d.get("stderr", ""),
        mutations=d.get("mutations", {}),
    )
