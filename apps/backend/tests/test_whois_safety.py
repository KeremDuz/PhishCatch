import subprocess
from types import SimpleNamespace

import pytest

from app.services.whois_scanner import WhoisScanner


@pytest.mark.parametrize(
    "hostname", ["--help", "-h.example.org", "example-.org", "invalid_label.example.org"]
)
def test_invalid_dns_names_never_become_whois_options(monkeypatch, hostname):
    def forbid_run(*args, **kwargs):
        pytest.fail("Invalid DNS labels must not start a native process")

    monkeypatch.setattr(subprocess, "run", forbid_run)
    result = WhoisScanner().scan(f"https://{hostname}/")
    assert result.verdict == "unknown" and result.status == "unavailable"
    assert result.details == {"signal": "invalid_hostname"}


def test_whois_uses_end_of_options_and_bounded_timeout(monkeypatch):
    calls = []

    def run(arguments, **options):
        calls.append((arguments, options))
        return SimpleNamespace(stdout="Creation Date: 2020-01-01T00:00:00Z\n")

    monkeypatch.setattr(subprocess, "run", run)
    result = WhoisScanner().scan("https://example.org/check")
    assert calls == [
        (["whois", "--", "example.org"], {"capture_output": True, "text": True, "timeout": 3})
    ]
    assert result.status == "completed" and result.verdict == "clean"


def test_native_whois_timeout_is_failed_evidence(monkeypatch):
    def expired(arguments, **options):
        raise subprocess.TimeoutExpired(arguments, options["timeout"])

    monkeypatch.setattr(subprocess, "run", expired)
    result = WhoisScanner().scan("https://example.org/")
    assert result.verdict == "unknown" and result.status == "failed"
    assert "timed out" in result.reason
