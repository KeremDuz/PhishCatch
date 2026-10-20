"""Fetch one public URL hop with its checked DNS answer pinned to the socket.

The original hostname remains in Host, TLS SNI and certificate verification.
Automatic redirects, environment proxies and netrc credentials are never used.
Callers must close the response and check each redirect as a fresh request.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from time import monotonic
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from requests.models import PreparedRequest
from urllib3 import HTTPConnectionPool, HTTPSConnectionPool

from app.services.url_safety import validate_public_http_url

BODY_BUDGET_SECONDS = 15.0
MAX_SOCKET_TIMEOUT_SECONDS = 5.0


class UnsafeUrlError(requests.RequestException):
    """The destination is not a globally routable HTTP(S) endpoint."""


class _PinnedHTTPAdapter(HTTPAdapter):
    def __init__(self, url: str, address: str) -> None:
        super().__init__(max_retries=0)
        self._url = url
        parsed = urlsplit(url)
        hostname = parsed.hostname
        if hostname is None:
            raise UnsafeUrlError("URL does not include a hostname")
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if parsed.scheme == "https":
            self._pinned_pool: HTTPConnectionPool = HTTPSConnectionPool(
                host=address,
                port=port,
                maxsize=1,
                block=True,
                # Dial the validated IP but authenticate the requested hostname.
                server_hostname=hostname,
                assert_hostname=hostname,
                cert_reqs="CERT_REQUIRED",
                ca_certs=requests.certs.where(),
            )
        else:
            self._pinned_pool = HTTPConnectionPool(
                host=address, port=port, maxsize=1, block=True
            )

    def get_connection_with_tls_context(
        self,
        request: PreparedRequest,
        verify: bool | str,
        proxies: Mapping[str, str] | None = None,
        cert: str | tuple[str, str] | None = None,
    ) -> HTTPConnectionPool:
        if request.url != self._url or verify is not True or proxies or cert:
            raise UnsafeUrlError("Only the validated, verified destination is allowed")
        return self._pinned_pool

    def close(self) -> None:
        self._pinned_pool.close()
        super().close()


class PublicHttpResponse:
    def __init__(self, response: requests.Response, adapter: _PinnedHTTPAdapter) -> None:
        self._response = response
        self._adapter = adapter
        self._body_deadline = monotonic() + BODY_BUDGET_SECONDS

    @property
    def headers(self) -> Mapping[str, str]:
        return self._response.headers

    @property
    def status_code(self) -> int:
        return self._response.status_code

    @property
    def is_redirect(self) -> bool:
        return self._response.is_redirect

    def raise_for_status(self) -> None:
        self._response.raise_for_status()

    def iter_content(self, chunk_size: int) -> Iterator[bytes]:
        if chunk_size <= 0:
            raise ValueError("Chunk size must be positive")
        try:
            while True:
                remaining = self._body_deadline - monotonic()
                if remaining <= 0:
                    raise requests.ReadTimeout("HTTP body exceeded the analysis time budget")
                raw = self._response.raw
                connection = raw.connection
                if connection is not None and connection.sock is not None:
                    connection.sock.settimeout(min(MAX_SOCKET_TIMEOUT_SECONDS, remaining))
                # read1 returns currently available data instead of waiting for
                # a full 100KB chunk while a hostile server slowly drips bytes.
                # Decoding is deliberately disabled: a decompressor's internal
                # read loop could defeat this check before producing output.
                chunk = raw.read1(chunk_size, decode_content=False)
                if monotonic() >= self._body_deadline:
                    raise requests.ReadTimeout("HTTP body exceeded the analysis time budget")
                if not chunk:
                    break
                yield chunk
        finally:
            self.close()

    def close(self) -> None:
        try:
            self._response.close()
        finally:
            self._adapter.close()

    def __enter__(self) -> PublicHttpResponse:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def public_http_request(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout: float = 5,
) -> PublicHttpResponse:
    if method not in {"HEAD", "GET"}:
        raise UnsafeUrlError("Only read-only HTTP requests are allowed")
    try:
        # Requests normalizes an explicit :0 away, so reject it before preparing
        # the URL rather than silently dialing a different destination port.
        if urlsplit(url).port == 0:
            raise UnsafeUrlError("URL port is invalid")
    except ValueError as exc:
        raise UnsafeUrlError("URL authority is invalid") from exc
    prepared = requests.Request(method, url, headers=dict(headers or {})).prepare()
    if prepared.url is None:
        raise UnsafeUrlError("URL is invalid")
    safety = validate_public_http_url(prepared.url)
    addresses = (safety.details or {}).get("resolved_ips")
    if not safety.is_safe or not isinstance(addresses, list) or not addresses:
        raise UnsafeUrlError(safety.reason or "No public destination was resolved")

    # Request.prepare does not load proxy, netrc or cookies from the environment.
    parsed = urlsplit(prepared.url)
    prepared.headers["Host"] = parsed.netloc
    prepared.headers["Accept-Encoding"] = "identity"
    adapter = _PinnedHTTPAdapter(prepared.url, str(addresses[0]))
    try:
        response = adapter.send(
            prepared,
            stream=True,
            timeout=(min(timeout, MAX_SOCKET_TIMEOUT_SECONDS), min(timeout, MAX_SOCKET_TIMEOUT_SECONDS)),
            verify=True,
            proxies={},
        )
        if response.headers.get("Content-Encoding", "identity").strip().lower() not in {"", "identity"}:
            response.close()
            raise requests.RequestException("Encoded HTTP bodies cannot be analysed within the bounded reader")
    except BaseException:
        adapter.close()
        raise
    return PublicHttpResponse(response, adapter)
