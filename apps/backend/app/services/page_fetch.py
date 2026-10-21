"""One bounded GET artifact per analysis; raw bodies never enter stage metadata/cache."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from time import monotonic
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

from app.services.safe_http import public_http_request
from app.services.url_safety import validate_public_http_url

MAX_HTML_BYTES = 1024 * 1024
MAX_REDIRECTS = 5
FETCH_BUDGET_SECONDS = 30.0
HTML_TYPES = {"text/html", "application/xhtml+xml"}
JSON_TYPES = {"application/json", "application/rdap+json"}


class FetchFailure(requests.RequestException):
    def __init__(
        self,
        code: str,
        safety: dict[str, object] | None = None,
        *,
        redirect_chain: tuple[dict[str, object], ...] = (),
        resolved_url: str | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.safety = safety
        self.redirect_chain = redirect_chain
        self.resolved_url = resolved_url

    def to_wire(self) -> dict[str, object]:
        return {
            "error": self.code,
            "safety": self.safety,
            "redirect_chain": list(self.redirect_chain),
            "resolved_url": self.resolved_url,
        }

    @classmethod
    def from_wire(cls, value: dict[str, object], original_url: str) -> FetchFailure:
        """Check bounded worker metadata; it does not authorize any connection."""
        chain = value.get("redirect_chain", [])
        resolved = value.get("resolved_url")
        safety = value.get("safety")
        if not isinstance(chain, list) or len(chain) > MAX_REDIRECTS:
            raise ValueError("Invalid failure chain")
        if safety is not None and not isinstance(safety, dict):
            raise ValueError("Invalid failure safety metadata")
        expected = original_url
        validated: list[dict[str, object]] = []
        for hop in chain:
            if not isinstance(hop, dict) or set(hop) != {"from", "to", "status_code", "kind"}:
                raise ValueError("Invalid failure hop")
            if hop["from"] != expected or not _public_url_shape(hop["from"]) or not _public_url_shape(hop["to"]):
                raise ValueError("Invalid failure target")
            if type(hop["status_code"]) is not int or not 100 <= hop["status_code"] <= 599:
                raise ValueError("Invalid failure status")
            if hop["kind"] not in {"http", "meta_refresh"}:
                raise ValueError("Invalid failure redirect kind")
            validated.append(dict(hop))
            expected = hop["to"]
        if resolved is not None and (resolved != expected or not _public_url_shape(resolved)):
            raise ValueError("Invalid failure resolved target")
        if chain and resolved is None:
            raise ValueError("Missing failure resolved target")
        return cls(str(value["error"]), safety, redirect_chain=tuple(validated), resolved_url=resolved)


def _public_url_shape(value: object) -> bool:
    """Reject impossible private worker targets without doing unbounded DNS."""
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        return False
    try:
        parsed = urlsplit(value)
        hostname = (parsed.hostname or "").rstrip(".").lower()
        if (
            parsed.scheme not in {"http", "https"}
            or not hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port == 0
            or hostname in {"localhost", "localhost.localdomain"}
            or hostname.endswith(".localhost")
        ):
            return False
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            return True  # DNS was validated by the fixed fetch worker.
        from app.services.url_safety import _is_blocked_ip

        return not _is_blocked_ip(address)
    except (ValueError, UnicodeError):
        return False


@dataclass
class _FetchProgress:
    chain: list[dict[str, object]]
    safe_hop_count: int = 0
    last_safe_url: str | None = None


@dataclass(frozen=True)
class PageArtifact:
    original_url: str
    final_url: str
    status_code: int
    content_type: str
    body: bytes
    redirect_chain: tuple[dict[str, object], ...]
    fetched_at: str

    @property
    def body_sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    def metadata(self) -> dict[str, object]:
        return {
            "method": "GET",
            "original_url": self.original_url,
            "resolved_url": self.final_url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "redirect_chain": list(self.redirect_chain),
            "fetched_at": self.fetched_at,
            "body_sha256": self.body_sha256,
        }

    def to_wire(self) -> dict[str, object]:
        return {**self.metadata(), "body": base64.b64encode(self.body).decode("ascii")}

    @classmethod
    def from_wire(cls, value: dict[str, object]) -> PageArtifact:
        body = base64.b64decode(str(value["body"]), validate=True)
        if (
            len(body) > MAX_HTML_BYTES
            or hashlib.sha256(body).hexdigest() != value["body_sha256"]
        ):
            raise ValueError("Invalid buffered body")
        for key in ("original_url", "final_url"):
            if not isinstance(value[key], str) or len(value[key]) > 2048:
                raise ValueError("Invalid buffered URL")
        if (
            not isinstance(value["redirect_chain"], list)
            or len(value["redirect_chain"]) > MAX_REDIRECTS
        ):
            raise ValueError("Invalid redirect chain")
        return cls(
            str(value["original_url"]),
            str(value["final_url"]),
            int(value["status_code"]),
            str(value["content_type"]),
            body,
            tuple(value["redirect_chain"]),
            str(value["fetched_at"]),
        )


_session: ContextVar[dict[str, PageArtifact | FetchFailure] | None] = ContextVar(
    "page_fetch", default=None
)
_use_worker: ContextVar[bool] = ContextVar("page_fetch_worker", default=False)


@contextmanager
def page_fetch_session(use_worker: bool = False):
    token = _session.set({})
    worker_token = _use_worker.set(use_worker)
    try:
        yield
    finally:
        _session.reset(token)
        _use_worker.reset(worker_token)


class BufferedPageResponse:
    def __init__(self, page: PageArtifact) -> None:
        self.page = page
        self.headers: Mapping[str, str] = {"Content-Type": page.content_type}

    def raise_for_status(self) -> None:
        if self.page.status_code >= 400:
            raise requests.HTTPError("Target returned an unsuccessful HTTP status")

    def iter_content(self, chunk_size: int) -> Iterator[bytes]:
        for start in range(0, len(self.page.body), chunk_size):
            yield self.page.body[start : start + chunk_size]

    def close(self) -> None:
        pass


def _meta_refresh(body: bytes, url: str) -> str | None:
    soup = BeautifulSoup(body, "lxml")
    for meta in soup.find_all("meta", attrs={"http-equiv": True}, limit=30):
        if str(meta.get("http-equiv", "")).lower() != "refresh":
            continue
        match = re.fullmatch(
            r"\s*\d+(?:\.\d+)?\s*;\s*url\s*=\s*(.+?)\s*",
            str(meta.get("content", "")),
            re.IGNORECASE,
        )
        if match:
            target = match.group(1).strip("\"'")
            base = soup.find("base", href=True)
            return urljoin(urljoin(url, str(base.get("href"))) if base else url, target)
    return None


def fetch_page(url: str, headers: Mapping[str, str] | None = None) -> PageArtifact:
    cache = _session.get()
    if cache is not None and url in cache:
        existing = cache[url]
        if isinstance(existing, FetchFailure):
            raise existing
        return existing
    try:
        if _use_worker.get():
            from app.services.worker_process import WorkerFailure, run_worker

            try:
                result = run_worker("fetch", {"url": url}, timeout=35)
                if "error" in result:
                    raise FetchFailure.from_wire(result, url)
                page = PageArtifact.from_wire(result["page"])
            except WorkerFailure as exc:
                raise FetchFailure(exc.code) from None
            except (KeyError, ValueError, TypeError):
                raise FetchFailure("invalid_worker_response") from None
        else:
            page = _fetch_page(url, headers)
    except FetchFailure as exc:
        if cache is not None:
            cache[url] = exc
            if exc.resolved_url is not None:
                cache[exc.resolved_url] = exc
        raise
    except requests.RequestException as exc:
        failure = FetchFailure("fetch_failed")
        if cache is not None:
            cache[url] = failure
        raise failure from exc
    if cache is not None:
        cache[url] = page
        cache[page.final_url] = page
    return page


def _fetch_page(url: str, headers: Mapping[str, str] | None) -> PageArtifact:
    progress = _FetchProgress([])
    try:
        return _fetch_page_with_progress(url, headers, progress)
    except requests.RequestException as exc:
        failure = exc if isinstance(exc, FetchFailure) else FetchFailure("fetch_failed")
        # A redirect is observed before its destination's safety validation.
        # Retain only hops whose two endpoints passed that validation.
        failure.redirect_chain = tuple(
            dict(hop) for hop in progress.chain[:progress.safe_hop_count]
        )
        failure.resolved_url = progress.last_safe_url
        raise failure from None


def _fetch_page_with_progress(
    url: str, headers: Mapping[str, str] | None, progress: _FetchProgress
) -> PageArtifact:
    if headers is None:
        headers = {
            "User-Agent": "PhishCatch/0.2 (+https://github.com/KeremDuz/PhishCatch)",
            "Accept": "text/html,application/xhtml+xml,application/json,application/rdap+json;q=0.9",
        }
    current = url
    chain = progress.chain
    deadline = monotonic() + FETCH_BUDGET_SECONDS
    for _ in range(MAX_REDIRECTS + 1):
        if monotonic() >= deadline:
            raise FetchFailure("fetch_deadline")
        safety = validate_public_http_url(current)
        if not safety.is_safe:
            raise FetchFailure(
                "unsafe_destination",
                {**(safety.details or {}), "reason": safety.reason},
            )
        progress.safe_hop_count = len(chain)
        progress.last_safe_url = current
        with public_http_request(
            "GET",
            current,
            headers=headers,
            timeout=min(5.0, max(0.01, deadline - monotonic())),
            allow_gzip=True,
        ) as response:
            status = response.status_code
            content_type = response.headers.get("Content-Type", "")
            next_url = None
            kind = "http"
            if response.is_redirect:
                location = response.headers.get("Location")
                if not location:
                    raise FetchFailure("redirect_without_location")
                next_url = urljoin(current, location)
                body = b""
            else:
                body = bytearray()
                media_type = content_type.split(";", 1)[0].strip().lower()
                if status < 400 and media_type in HTML_TYPES | JSON_TYPES:
                    for chunk in response.iter_content(chunk_size=64 * 1024):
                        if monotonic() >= deadline:
                            raise FetchFailure("fetch_deadline")
                        if len(body) + len(chunk) > MAX_HTML_BYTES:
                            raise FetchFailure("html_too_large")
                        body.extend(chunk)
                    next_url = (
                        _meta_refresh(bytes(body), current)
                        if media_type in HTML_TYPES
                        else None
                    )
                    kind = "meta_refresh"
                if not next_url:
                    return PageArtifact(
                        url,
                        current,
                        status,
                        content_type,
                        bytes(body),
                        tuple(chain),
                        datetime.now(UTC).isoformat(),
                    )
            if len(next_url) > 2048 or next_url == current:
                raise FetchFailure("invalid_redirect")
            chain.append(
                {"from": current, "to": next_url, "status_code": status, "kind": kind}
            )
            current = next_url
    raise FetchFailure("redirect_limit")
