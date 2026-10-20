from app.core import scan_cache
from app.core.scan_cache import ScannerResultCache
from app.models.schemas import StageResult


def test_transient_failure_can_recover_immediately():
    cache = ScannerResultCache()
    cache.set(
        "URLhausScanner",
        "https://example.com/",
        StageResult(scanner="URLhausScanner", verdict="unknown", status="unavailable"),
    )
    assert cache.get("URLhausScanner", "https://example.com/") is None


def test_unrelated_access_purges_all_expired_entries(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(scan_cache.time, "monotonic", lambda: now[0])
    cache = ScannerResultCache(ttl_seconds=10)
    cache.set(
        "MLModelScanner",
        "https://old.example/",
        StageResult(scanner="MLModelScanner", verdict="clean"),
    )
    now[0] = 11
    assert cache.get("MLModelScanner", "https://new.example/") is None
    assert not cache._entries


def test_page_content_is_not_reused_without_a_current_fetch():
    cache = ScannerResultCache()
    for name in ("HtmlScraper", "UrlResolver"):
        cache.set(
            name, "https://example.com/", StageResult(scanner=name, verdict="clean")
        )
        assert cache.get(name, "https://example.com/") is None


def test_nonmatch_reputation_has_shorter_ttl_and_policy_is_in_key(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(scan_cache.time, "monotonic", lambda: now[0])
    cache = ScannerResultCache(ttl_seconds=900)
    cache.set(
        "URLhausScanner",
        "https://example.com/",
        StageResult(scanner="URLhausScanner", verdict="unknown"),
    )
    assert (
        cache.get("URLhausScanner", "https://example.com/").details["cache"][
            "ttl_seconds"
        ]
        == 60
    )
    now[0] = 61
    assert cache.get("URLhausScanner", "https://example.com/") is None
    assert cache._key("MLModelScanner", "https://example.com/") != ScannerResultCache(
        version="other"
    )._key("MLModelScanner", "https://example.com/")
