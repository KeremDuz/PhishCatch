"""One socket request per container lifetime; no network, secrets or persistent jobs."""

from __future__ import annotations

import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from app.services.offline_renderer_protocol import (
    MAX_WIRE_BYTES,
    SOCKET_PATH,
    decode_message,
    encode_message,
    read_frame,
    unavailable,
    validate_request,
    validate_response,
    write_frame,
)
from app.services.offline_renderer_runtime import isolated_runtime


def _kill_group(child: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def bounded_render(request: dict[str, Any]) -> dict[str, object]:
    """The parent kills/reaps actual browser processes, independent of clients."""
    validate_request(request)
    code = (
        "import sys,resource; sys.path.insert(0,'/app'); "
        "resource.setrlimit(resource.RLIMIT_CORE,(0,0)); "
        "resource.setrlimit(resource.RLIMIT_CPU,(10,11)); "
        f"resource.setrlimit(resource.RLIMIT_FSIZE,({MAX_WIRE_BYTES},{MAX_WIRE_BYTES})); "
        "from app.services.offline_renderer_runtime import main; main()"
    )
    with tempfile.TemporaryFile() as output:
        child = subprocess.Popen(
            [sys.executable, "-I", "-c", code],
            stdin=subprocess.PIPE,
            stdout=output,
            stderr=subprocess.DEVNULL,
            cwd="/app",
            env={
                "PATH": os.defpath,
                "LANG": "C.UTF-8",
                "HOME": "/tmp",
                "PLAYWRIGHT_BROWSERS_PATH": "/ms-playwright",
            },
            start_new_session=True,
        )
        try:
            child.communicate(encode_message(request), timeout=request["timeout_ms"] / 1000 + 2)
            if child.returncode != 0:
                return unavailable(request, "render_failed")
            output.seek(0)
            result = decode_message(output.read(MAX_WIRE_BYTES + 1))
            validate_response(result, request)
            return result
        except subprocess.TimeoutExpired:
            return unavailable(request, "render_deadline")
        except (ValueError, TypeError, KeyError, UnicodeError):
            return unavailable(request, "render_failed")
        finally:
            # Also kill orphan browser descendants after a normal Python exit.
            _kill_group(child)
            child.communicate()


def serve_once() -> None:
    if not isolated_runtime():
        raise RuntimeError("Renderer requires an unprivileged network-none runtime")
    os.umask(0o007)
    path = Path(SOCKET_PATH)
    if path.is_symlink():
        raise RuntimeError("Socket path cannot be a symlink")
    if path.exists():
        old = path.stat()
        if not stat.S_ISSOCK(old.st_mode) or old.st_uid != os.geteuid():
            raise RuntimeError("Unexpected renderer socket entry")
        path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(SOCKET_PATH)
        os.chmod(SOCKET_PATH, 0o660)
        server.listen(1)
        connection, _ = server.accept()
        # Closing the listening socket prevents an unbounded job queue. Docker
        # restart:always supplies a fresh filesystem/process namespace next job.
        server.close()
        with connection:
            request = read_frame(connection, 2)
            validate_request(request)
            result = bounded_render(request)
            connection.settimeout(2)
            write_frame(connection, result)


def main() -> None:
    try:
        serve_once()
    except Exception:  # noqa: BLE001 - never log submitted HTML, URLs or browser output.
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
