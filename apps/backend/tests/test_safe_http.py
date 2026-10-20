"""Public URL fetches must not reach the scanner host's private networks."""

import io
import ipaddress
import socket
from types import SimpleNamespace

import pytest
import requests
from urllib3 import HTTPConnectionPool
from urllib3.response import HTTPResponse

from app.services import safe_http, url_safety
from app.services.html_scraper_scanner import HtmlScraperScanner
from app.services.url_resolver_scanner import UrlResolverScanner


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "100.87.174.61",
        "100.127.255.254",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fd7a:115c:a1e0::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "::ffff:8.8.8.8",
        "2002:7f00:1::",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "64:ff9b::7f00:1",
        "64:ff9b:1::a00:1",
    ],
)
def test_non_public_and_transition_addresses_never_open_a_connection(
    monkeypatch, address
):
    def forbid_send(*args, **kwargs):
        pytest.fail("A blocked destination must never reach the HTTP transport")

    monkeypatch.setattr(safe_http._PinnedHTTPAdapter, "send", forbid_send)
    host = f"[{address}]" if ":" in address else address
    with pytest.raises(safe_http.UnsafeUrlError):
        safe_http.public_http_request("GET", f"http://{host}/")


@pytest.mark.parametrize("address", ["8.8.8.8", "2606:4700:4700::1111"])
def test_global_unicast_addresses_are_allowed(address):
    assert not url_safety._is_blocked_ip(ipaddress.ip_address(address))


def test_mixed_public_and_private_dns_answers_are_rejected(monkeypatch):
    monkeypatch.setattr(
        url_safety,
        "_resolve_hostname",
        lambda hostname: [ipaddress.ip_address("8.8.8.8"), ipaddress.ip_address("10.0.0.1")],
    )
    with pytest.raises(safe_http.UnsafeUrlError):
        safe_http.public_http_request("GET", "https://mixed.example/")


def test_dns_rebinding_cannot_change_the_actual_dial_target(monkeypatch):
    resolutions = []
    dial_targets = []

    def rebinding_dns(host, port, **kwargs):
        resolutions.append(host)
        value = "8.8.8.8" if len(resolutions) == 1 else "127.0.0.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (value, port or 0))]

    def capture_dial(address, *args, **kwargs):
        dial_targets.append(address)
        raise OSError("No network is opened in this test")

    monkeypatch.setattr(socket, "getaddrinfo", rebinding_dns)
    monkeypatch.setattr("urllib3.util.connection.create_connection", capture_dial)
    with pytest.raises(requests.ConnectionError):
        safe_http.public_http_request("GET", "https://rebind.example/check")
    assert resolutions == ["rebind.example"]
    assert dial_targets == [("8.8.8.8", 443)]


def test_https_preserves_host_sni_and_certificate_checks_without_proxy_or_netrc(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(
        url_safety,
        "_resolve_hostname",
        lambda hostname: [ipaddress.ip_address("8.8.8.8")],
    )
    netrc = tmp_path / "netrc"
    netrc.write_text("machine original.example login private password secret\n")
    monkeypatch.setenv("NETRC", str(netrc))
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "untrusted.pem"))
    observed = {}

    def capture(pool, method, url, **kwargs):
        observed.update(
            pool=pool,
            target=pool.host,
            port=pool.port,
            sni=pool.conn_kw["server_hostname"],
            hostname=pool.assert_hostname,
            verification=pool.cert_reqs,
            ca=pool.ca_certs,
            method=method,
            url=url,
            options=kwargs,
        )
        return HTTPResponse(
            body=io.BytesIO(b"<html>hello</html>"),
            headers={"Content-Type": "text/html"},
            status=200,
            preload_content=False,
        )

    monkeypatch.setattr(HTTPConnectionPool, "urlopen", capture)
    with safe_http.public_http_request(
        "GET", "https://original.example:8443/page?a=1", headers={"Host": "wrong.example"}
    ) as response:
        assert b"".join(response.iter_content(100)) == b"<html>hello</html>"
    assert observed["target"] == "8.8.8.8" and observed["port"] == 8443
    assert observed["sni"] == observed["hostname"] == "original.example"
    assert observed["verification"] == "CERT_REQUIRED" and observed["ca"]
    assert observed["method"] == "GET" and observed["url"] == "/page?a=1"
    assert observed["options"]["redirect"] is False
    assert observed["options"]["headers"]["Host"] == "original.example:8443"
    assert "Authorization" not in observed["options"]["headers"]
    assert observed["pool"].pool is None


@pytest.mark.parametrize("target", ["http://127.0.0.1/", "http://100.87.174.61/", "http://[::1]/"])
@pytest.mark.parametrize("scanner_kind", ["html", "resolver"])
def test_redirects_are_revalidated_before_next_connection(monkeypatch, target, scanner_kind):
    monkeypatch.setattr(
        url_safety,
        "_resolve_hostname",
        lambda hostname: [
            ipaddress.ip_address(hostname if hostname.replace(".", "").isdigit() or ":" in hostname else "8.8.8.8")
        ],
    )
    pools = []

    def redirect(pool, method, url, **kwargs):
        pools.append(pool)
        assert pool.host == "8.8.8.8"
        return HTTPResponse(
            body=io.BytesIO(b""),
            status=302,
            headers={"Location": target},
            preload_content=False,
        )

    monkeypatch.setattr(HTTPConnectionPool, "urlopen", redirect)
    scanner = HtmlScraperScanner() if scanner_kind == "html" else UrlResolverScanner()
    result = scanner.scan("http://original.example/")
    assert result.verdict == "unknown"
    assert len(pools) == 1 and pools[0].pool is None
    if scanner_kind == "html":
        assert result.status == "failed"
    else:
        assert result.details["safety"]["blocked_ips"]


def test_invalid_authorities_and_embedded_credentials_never_fetch(monkeypatch):
    def forbid_send(*args, **kwargs):
        pytest.fail("Invalid authority must never reach the HTTP transport")

    monkeypatch.setattr(safe_http._PinnedHTTPAdapter, "send", forbid_send)
    for url in ("https://user:secret@8.8.8.8/", "https://8.8.8.8:99999/", "http://8.8.8.8:0/"):
        with pytest.raises((safe_http.UnsafeUrlError, requests.exceptions.InvalidURL)):
            safe_http.public_http_request("GET", url)


def test_html_stream_failure_closes_the_response(monkeypatch):
    class BrokenResponse:
        headers = {"Content-Type": "text/html"}
        closed = False

        def raise_for_status(self):
            pass

        def iter_content(self, chunk_size):
            yield b"<html>"
            raise requests.ReadTimeout("Interrupted body")

        def close(self):
            self.closed = True

    response = BrokenResponse()
    scanner = HtmlScraperScanner()
    monkeypatch.setattr(scanner, "_safe_get", lambda url, headers: (response, url, []))
    result = scanner.scan("https://original.example/")
    assert result.status == "failed" and result.verdict == "unknown"
    assert response.closed


def test_optional_browser_flag_cannot_launch_an_unisolated_browser(monkeypatch):
    from app.services.browser_renderer import render_page

    def forbid_dns(*args, **kwargs):
        pytest.fail("Unavailable rendering must not start any network request")

    monkeypatch.setattr(socket, "getaddrinfo", forbid_dns)
    rendered = render_page("https://original.example/", screenshot=True)
    assert not rendered.available and "isolated" in rendered.reason

    class DynamicResponse:
        headers = {"Content-Type": "text/html"}

        def raise_for_status(self):
            pass

        def iter_content(self, chunk_size):
            yield b"<html><body><div id='root'></div><script>load()</script></body></html>"

        def close(self):
            pass

    scanner = HtmlScraperScanner(browser_render_enabled=True)
    monkeypatch.setattr(
        scanner, "_safe_get", lambda url, headers: (DynamicResponse(), url, [])
    )
    result = scanner.scan("https://original.example/")
    assert result.status == "completed" and result.verdict == "unknown"
    assert result.details["dynamic_analysis"]["required"] is True
    assert "isolated" in result.details["browser_render"]["reason"]


def test_slow_drip_body_hits_wall_budget_and_closes_transport(monkeypatch):
    clock = SimpleNamespace(now=100.0)
    monkeypatch.setattr(safe_http, "monotonic", lambda: clock.now)
    socket_timeouts = []
    closed = []

    class DripRaw:
        connection = SimpleNamespace(
            sock=SimpleNamespace(settimeout=socket_timeouts.append)
        )
        calls = 0

        def read1(self, amount, *, decode_content):
            assert amount == 8192 and decode_content is False
            self.calls += 1
            clock.now += 3
            return b"x"

        def close(self):
            closed.append("body")

    raw = DripRaw()
    response = requests.Response()
    response.raw = raw
    wrapped = safe_http.PublicHttpResponse(
        response, SimpleNamespace(close=lambda: closed.append("adapter"))
    )
    received = []
    with pytest.raises(requests.ReadTimeout, match="time budget"):
        for chunk in wrapped.iter_content(8192):
            received.append(chunk)
    assert clock.now == 115.0 and raw.calls == 5
    # Data arriving at/after expiry never reaches feature extraction.
    assert received == [b"x"] * 4
    assert socket_timeouts == [5.0, 5.0, 5.0, 5.0, 3.0]
    assert closed == ["body", "adapter"]


def test_body_read_failure_always_closes_transport():
    closed = []

    class FailingRaw:
        connection = None

        def read1(self, amount, *, decode_content):
            raise requests.ReadTimeout("Socket read timed out")

        def close(self):
            closed.append("body")

    response = requests.Response()
    response.raw = FailingRaw()
    wrapped = safe_http.PublicHttpResponse(
        response, SimpleNamespace(close=lambda: closed.append("adapter"))
    )
    with pytest.raises(requests.ReadTimeout):
        list(wrapped.iter_content(8192))
    assert closed == ["body", "adapter"]


def test_unexpected_content_encoding_is_rejected_before_decompression(monkeypatch):
    monkeypatch.setattr(
        url_safety,
        "_resolve_hostname",
        lambda hostname: [ipaddress.ip_address("8.8.8.8")],
    )
    pools = []

    def encoded_body(pool, method, url, **kwargs):
        pools.append(pool)
        return HTTPResponse(
            body=io.BytesIO(b"not-a-compressed-stream"),
            headers={"Content-Encoding": "gzip"},
            status=200,
            preload_content=False,
        )

    monkeypatch.setattr(HTTPConnectionPool, "urlopen", encoded_body)
    with pytest.raises(requests.RequestException, match="Encoded HTTP bodies"):
        safe_http.public_http_request("GET", "https://original.example/")
    assert pools[0].pool is None
