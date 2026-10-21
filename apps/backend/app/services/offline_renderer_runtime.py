"""One fresh sandboxed Chromium job. This process must have no network device."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from app.services.offline_renderer_protocol import (
    MAX_HTML_BYTES,
    MAX_WIRE_BYTES,
    VERSION,
    decode_message,
    encode_message,
    source_hash,
    unavailable,
    validate_request,
)


def isolated_runtime() -> bool:
    """Necessary runtime checks; Compose/network acceptance remains mandatory."""
    return (
        sys.platform == "linux"
        and os.geteuid() != 0
        and {path.name for path in Path("/sys/class/net").iterdir()} == {"lo"}
    )


def _navigation_identity(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def render_document(request: dict[str, Any]) -> dict[str, object]:
    validate_request(request)
    if not isolated_runtime():
        return unavailable(request, "render_failed")
    from playwright.sync_api import sync_playwright

    blocked_requests = 0
    supplied = False
    initial_navigation_url = ""
    browser = None
    try:
        with sync_playwright() as playwright:
            # Playwright defaults to sandbox=False; it is an explicit invariant.
            # A host unable to launch this sandbox gets unavailable, never a
            # retry using --no-sandbox, SYS_ADMIN or privileged mode.
            browser = playwright.chromium.launch(headless=True, chromium_sandbox=True)
            context = browser.new_context(
                service_workers="block",
                accept_downloads=False,
                permissions=[],
                bypass_csp=False,
            )
            context.set_default_timeout(request["timeout_ms"])
            def block_websocket(websocket: Any) -> None:
                nonlocal blocked_requests
                blocked_requests = min(65535, blocked_requests + 1)
                websocket.close()

            context.route_web_socket("**/*", block_websocket)
            page = context.new_page()

            def block_or_supply(route: Any) -> None:
                nonlocal blocked_requests, supplied, initial_navigation_url
                candidate = route.request
                if (
                    not supplied
                    and candidate.method == "GET"
                    and candidate.is_navigation_request()
                    and candidate.frame == page.main_frame
                    and _navigation_identity(candidate.url) == _navigation_identity(request["url"])
                ):
                    supplied = True
                    initial_navigation_url = candidate.url
                    route.fulfill(status=200, content_type="text/html; charset=utf-8", body=request["html"])
                    return
                # No route.continue(), route.fetch(), HTTP proxy, browser API
                # request context or bindings expose the analyzer's network.
                blocked_requests = min(65535, blocked_requests + 1)
                route.abort("blockedbyclient")

            context.route("**/*", block_or_supply)
            context.on("page", lambda other: other.close() if other != page else None)
            page.on("dialog", lambda dialog: dialog.dismiss())
            page.on("download", lambda download: download.cancel())
            page.goto(request["url"], wait_until="domcontentloaded", timeout=request["timeout_ms"])
            page.wait_for_timeout(300)
            if not supplied or _navigation_identity(page.url) != _navigation_identity(initial_navigation_url):
                return unavailable(request, "navigation_blocked")
            html = page.content()
            if len(html.encode()) > MAX_HTML_BYTES:
                return unavailable(request, "render_output_limit")
            title = page.title()[:256]
            # Do not read descendant frames or flatten origins into this HTML.
            visible_text = page.locator("body").inner_text(timeout=500)[:8192]
            return {
                "version": VERSION,
                "job_id": request["job_id"],
                "source_sha256": source_hash(request),
                "status": "rendered",
                "url": request["url"],
                "html": html,
                "title": title,
                "visible_text": visible_text,
                "blocked_requests": blocked_requests,
                "frame_count": min(65535, max(0, len(page.frames) - 1)),
                # Only original HTML and inline scripts were available. Even
                # zero attempted requests do not prove sensitive data flow.
                "coverage_complete": False,
            }
    except Exception:  # noqa: BLE001 - renderer exceptions must not expose page data.
        return unavailable(request, "render_failed")
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:  # noqa: BLE001, S110 - parent kills group; never log page data.
                pass


def main() -> None:
    if not isolated_runtime():
        raise SystemExit(78)
    request = decode_message(sys.stdin.buffer.read(MAX_WIRE_BYTES + 1))
    validate_request(request)
    sys.stdout.buffer.write(encode_message(render_document(request)))


if __name__ == "__main__":
    main()
