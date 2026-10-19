from __future__ import annotations

from dataclasses import dataclass

from app.services.url_safety import validate_public_http_url


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
    safety = validate_public_http_url(url)
    if not safety.is_safe:
        return BrowserRenderResult(available=False, final_url=url, reason=f"URL fetch blocked: {safety.reason}")

    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        return BrowserRenderResult(
            available=False,
            final_url=url,
            reason="Playwright is not installed",
            error=str(exc),
        )

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            page = browser.new_page(
                viewport={"width": 1366, "height": 768},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
                ),
            )
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            try:
                page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 2500))
            except PlaywrightTimeoutError:
                pass

            html = page.content()
            title = page.title()
            try:
                visible_text = page.locator("body").inner_text(timeout=1000)
            except PlaywrightError:
                visible_text = ""
            screenshot_bytes = len(page.screenshot(full_page=False)) if screenshot else 0
            final_url = page.url
            browser.close()

        return BrowserRenderResult(
            available=True,
            html=html,
            final_url=final_url,
            title=title,
            visible_text=visible_text[:20000],
            screenshot_bytes=screenshot_bytes,
            reason="Rendered with headless Chromium",
        )
    except Exception as exc:
        return BrowserRenderResult(
            available=False,
            final_url=url,
            reason="Browser render failed",
            error=str(exc),
        )
