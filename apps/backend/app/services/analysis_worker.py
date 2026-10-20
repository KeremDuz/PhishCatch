"""One private stdin/stdout analysis job; no server, credentials, or persistent state."""

from __future__ import annotations

import json
import os
import sys
import warnings


def main() -> None:
    os.umask(0o077)
    warnings.simplefilter("ignore")
    if os.name == "posix":
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (12, 13))
        resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
        resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024**2, 2 * 1024**2))
    from app.services.page_fetch import (
        BufferedPageResponse,
        FetchFailure,
        PageArtifact,
        _fetch_page,
    )

    try:
        raw = sys.stdin.buffer.read(2 * 1024**2 + 1)
        if len(raw) > 2 * 1024**2:
            raise ValueError("input_limit")
        job = json.loads(raw)
        payload = job["payload"]
        if job["kind"] == "validate":
            from dataclasses import asdict

            from app.services.url_safety import validate_public_http_url

            result = asdict(validate_public_http_url(payload["url"]))
        elif job["kind"] == "rdap":
            from app.services.rdap_scanner import registration_context

            result = registration_context(payload["url"])
        elif job["kind"] == "fetch":
            url = payload["url"]
            if not isinstance(url, str) or not 1 <= len(url) <= 2048:
                raise ValueError("invalid_url")
            result = {"page": _fetch_page(url, None).to_wire()}
        elif job["kind"] == "html":
            from app.services.html_scraper_scanner import HtmlScraperScanner

            page = PageArtifact.from_wire(payload["page"])
            scanner = HtmlScraperScanner(
                model_path=payload["model_path"], browser_render_enabled=False
            )
            scanner._safe_get = lambda url, headers: (
                BufferedPageResponse(page),
                page.final_url,
                list(page.redirect_chain),
            )
            stage = scanner.scan(page.final_url)
            result = {
                "stage": stage.model_dump(),
                "training_features": stage.training_features,
            }
        else:
            raise ValueError("invalid_job")
    except FetchFailure as exc:
        result = {"error": exc.code, "safety": exc.safety}
    except Exception:  # noqa: BLE001 - redact every worker diagnostic at the boundary.
        result = {"error": "analysis_worker_failed"}
    output = json.dumps(result, allow_nan=False).encode()
    if len(output) > 2 * 1024**2:
        output = b'{"error":"worker_output_limit"}'
    sys.stdout.buffer.write(output)


if __name__ == "__main__":
    main()
