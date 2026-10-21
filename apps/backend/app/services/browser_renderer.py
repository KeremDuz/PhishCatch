from __future__ import annotations

import secrets
import socket
from dataclasses import dataclass

from app.services.offline_renderer_protocol import (
    MAX_TIMEOUT_MS,
    SOCKET_PATH,
    VERSION,
    read_frame,
    validate_request,
    validate_response,
    write_frame,
)


@dataclass(frozen=True)
class BrowserRenderResult:
    available: bool
    html: str = ""
    final_url: str = ""
    title: str = ""
    visible_text: str = ""
    screenshot_bytes: int = 0
    reason: str = ""
    error: str = ""
    coverage_complete: bool = False
    blocked_requests: int = 0
    frame_count: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "available": self.available,
            "final_url": self.final_url,
            "title": self.title,
            "html_length": len(self.html),
            "visible_text_length": len(self.visible_text),
            "screenshot_bytes": self.screenshot_bytes,
            "reason": self.reason,
            "error": self.error,
            "mode": VERSION,
            "coverage_complete": self.coverage_complete,
            "blocked_requests": self.blocked_requests,
            "frame_count": self.frame_count,
        }


def render_page(
    url: str,
    timeout_ms: int = 7000,
    screenshot: bool = False,
    *,
    raw_html: str | None = None,
    socket_path: str | None = None,
) -> BrowserRenderResult:
    """Send buffered source to an offline worker; never start a local browser."""
    if socket_path != SOCKET_PATH or raw_html is None or not hasattr(socket, "AF_UNIX"):
        return BrowserRenderResult(available=False, final_url=url, reason="An isolated offline renderer is not configured")
    if screenshot:
        return BrowserRenderResult(available=False, final_url=url, reason="Offline screenshots are not supported")
    request: dict[str, object] = {
        "version": VERSION,
        "job_id": secrets.token_hex(16),
        "url": url,
        "html": raw_html,
        "timeout_ms": min(MAX_TIMEOUT_MS, max(250, timeout_ms)),
    }
    try:
        validate_request(request)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(1)
            connection.connect(socket_path)
            connection.settimeout(2)
            write_frame(connection, request)
            result = read_frame(connection, request["timeout_ms"] / 1000 + 3)
        validate_response(result, request)
        if result["status"] != "rendered":
            return BrowserRenderResult(available=False, final_url=url, reason="Offline renderer unavailable", error=result["error"])
        return BrowserRenderResult(
            available=True,
            html=result["html"],
            final_url=url,
            title=result["title"],
            visible_text=result["visible_text"],
            coverage_complete=False,
            blocked_requests=result["blocked_requests"],
            frame_count=result["frame_count"],
            reason="Original HTML rendered offline; external resources and sensitive data flow remain unassessed",
        )
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        return BrowserRenderResult(available=False, final_url=url, reason="Offline renderer unavailable", error="offline_render_failed")
