from __future__ import annotations

from dataclasses import dataclass


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
        }


def render_page(url: str, timeout_ms: int = 7000, screenshot: bool = False) -> BrowserRenderResult:
    # A URL check before page.goto does not constrain redirects, fetch(),
    # iframes or other browser subresources. Do not launch an unisolated browser
    # on the server's network, even if the optional environment flag is enabled.
    # Preserve this interface for a future isolated, egress-restricted worker.
    return BrowserRenderResult(
        available=False,
        final_url=url,
        reason="Browser rendering is disabled until an isolated egress worker is configured",
    )
