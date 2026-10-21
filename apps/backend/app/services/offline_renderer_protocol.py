"""Bounded Unix-socket protocol for original-HTML-only offline rendering."""

from __future__ import annotations

import hashlib
import json
import socket
import struct
from time import monotonic
from typing import Any
from urllib.parse import urlsplit

VERSION = "offline-dom-1"
SOCKET_PATH = "/run/phishcatch-renderer/renderer.sock"
MAX_HTML_BYTES = 1024 * 1024
MAX_WIRE_BYTES = 2 * 1024 * 1024
MAX_TIMEOUT_MS = 7000


class ProtocolError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate_field")
        result[key] = value
    return result


def encode_message(value: dict[str, object]) -> bytes:
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
    if len(raw) > MAX_WIRE_BYTES:
        raise ProtocolError("message_limit")
    return raw


def decode_message(raw: bytes) -> dict[str, Any]:
    if not 1 <= len(raw) <= MAX_WIRE_BYTES:
        raise ProtocolError("message_limit")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolError("invalid_message") from exc
    if not isinstance(value, dict):
        raise ProtocolError("invalid_message")
    return value


def read_frame(connection: socket.socket, timeout_seconds: float) -> dict[str, Any]:
    deadline = monotonic() + timeout_seconds

    def read_exact(size: int) -> bytes:
        pieces = bytearray()
        while len(pieces) < size:
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError("renderer_read_deadline")
            connection.settimeout(remaining)
            piece = connection.recv(min(size - len(pieces), 64 * 1024))
            if not piece:
                raise ProtocolError("truncated_message")
            pieces.extend(piece)
        return bytes(pieces)

    length = struct.unpack("!I", read_exact(4))[0]
    if not 1 <= length <= MAX_WIRE_BYTES:
        raise ProtocolError("message_limit")
    return decode_message(read_exact(length))


def write_frame(connection: socket.socket, value: dict[str, object]) -> None:
    raw = encode_message(value)
    connection.sendall(struct.pack("!I", len(raw)) + raw)


def validate_request(value: dict[str, Any]) -> None:
    if set(value) != {"version", "job_id", "url", "html", "timeout_ms"} or value["version"] != VERSION:
        raise ProtocolError("invalid_request")
    job_id = value["job_id"]
    if not isinstance(job_id, str) or len(job_id) != 32 or any(c not in "0123456789abcdef" for c in job_id):
        raise ProtocolError("invalid_job_id")
    url = value["url"]
    if not isinstance(url, str) or not 1 <= len(url) <= 2048:
        raise ProtocolError("invalid_url")
    try:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username is not None or parts.password is not None or parts.port == 0:
            raise ProtocolError("invalid_url")
    except ValueError as exc:
        raise ProtocolError("invalid_url") from exc
    if not isinstance(value["html"], str) or len(value["html"].encode()) > MAX_HTML_BYTES:
        raise ProtocolError("html_limit")
    if type(value["timeout_ms"]) is not int or not 250 <= value["timeout_ms"] <= MAX_TIMEOUT_MS:
        raise ProtocolError("invalid_timeout")


def source_hash(request: dict[str, Any]) -> str:
    return hashlib.sha256(request["html"].encode()).hexdigest()


def validate_response(value: dict[str, Any], request: dict[str, Any]) -> None:
    common = {"version", "job_id", "source_sha256", "status"}
    if value.get("version") != VERSION or value.get("job_id") != request["job_id"] or value.get("source_sha256") != source_hash(request):
        raise ProtocolError("response_identity_mismatch")
    if value.get("status") == "unavailable":
        if set(value) != common | {"error"} or value["error"] not in {"render_failed", "render_deadline", "render_output_limit", "navigation_blocked"}:
            raise ProtocolError("invalid_error_response")
        return
    if set(value) != common | {"url", "html", "title", "visible_text", "blocked_requests", "frame_count", "coverage_complete"} or value["status"] != "rendered":
        raise ProtocolError("invalid_response")
    if value["url"] != request["url"] or value["coverage_complete"] is not False:
        raise ProtocolError("invalid_coverage_claim")
    for key, limit in (("html", MAX_HTML_BYTES), ("title", 1024), ("visible_text", 32 * 1024)):
        if not isinstance(value[key], str) or len(value[key].encode()) > limit:
            raise ProtocolError("response_limit")
    for key in ("blocked_requests", "frame_count"):
        if type(value[key]) is not int or not 0 <= value[key] <= 65535:
            raise ProtocolError("invalid_response_count")


def unavailable(request: dict[str, Any], error: str) -> dict[str, object]:
    return {
        "version": VERSION,
        "job_id": request["job_id"],
        "source_sha256": source_hash(request),
        "status": "unavailable",
        "error": error,
    }
