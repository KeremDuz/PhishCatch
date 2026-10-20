"""Fixed analysis jobs with bounded lifetime/output and no inherited application secrets.

These are resource-limited processes, not a browser/network sandbox.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Literal

MAX_WIRE_BYTES = 2 * 1024 * 1024
BACKEND_ROOT = Path(__file__).resolve().parents[2]


class WorkerFailure(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def worker_environment() -> dict[str, str]:
    env = {
        "PATH": os.defpath,
        "LANG": "C.UTF-8",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
    }
    if os.name == "nt" and "SystemRoot" in os.environ:
        env["SystemRoot"] = os.environ["SystemRoot"]
    return env


def bounded_process(arguments: list[str], payload: bytes, timeout: float) -> bytes:
    if len(payload) > MAX_WIRE_BYTES:
        raise WorkerFailure("worker_input_limit")
    with tempfile.TemporaryFile() as output:
        child = subprocess.Popen(
            arguments,
            stdin=subprocess.PIPE,
            stdout=output,
            stderr=subprocess.DEVNULL,
            cwd=BACKEND_ROOT,
            env=worker_environment(),
            start_new_session=os.name == "posix",
        )
        try:
            child.communicate(input=payload, timeout=timeout)
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                child.kill()
            child.communicate()
            raise WorkerFailure("worker_timeout") from None
        except BaseException:
            child.kill()
            child.communicate()
            raise
        if child.returncode != 0:
            raise WorkerFailure("worker_failed")
        output.seek(0)
        result = output.read(MAX_WIRE_BYTES + 1)
        if len(result) > MAX_WIRE_BYTES:
            raise WorkerFailure("worker_output_limit")
        return result


def run_worker(
    kind: Literal["fetch", "html", "validate", "rdap"],
    payload: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    if kind not in {"fetch", "html", "validate", "rdap"}:
        raise WorkerFailure("invalid_worker_kind")
    # Code, interpreter and working directory are server-controlled. User URLs
    # travel through stdin, never through a shell or the process command line.
    code = f"import sys; sys.path.insert(0, {str(BACKEND_ROOT)!r}); from app.services.analysis_worker import main; main()"
    raw = bounded_process(
        [sys.executable, "-I", "-c", code],
        json.dumps({"kind": kind, "payload": payload}).encode(),
        timeout,
    )
    try:
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise TypeError
    except (ValueError, TypeError, UnicodeError):
        raise WorkerFailure("invalid_worker_response") from None
    return result
