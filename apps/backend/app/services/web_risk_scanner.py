"""Opt-in, bounded Web Risk Lookup; never submits URLs for scanning/training.

Only this server-controlled Google endpoint is contacted. The full eligible URL
is shared with Google: the operator must enable that policy explicitly.
"""

from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import sys
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import requests

from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner
from app.services.reputation_budget import LookupBudget, _budget
from app.services.reputation_budget import lookup_session as lookup_session
from app.services.worker_process import BACKEND_ROOT, WorkerFailure, bounded_process

API_URL = "https://webrisk.googleapis.com/v1/uris:search"
THREAT_TYPES = ("SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE")
MAX_RESPONSE_BYTES = 64 * 1024


class LookupQuota:
    """Atomic persistent UTC counters. Contains no URLs, keys or user identity."""

    def __init__(self, path: str | Path, daily: int, monthly: int) -> None:
        self.path = Path(path)
        self.daily = daily
        self.monthly = monthly

    def reserve(self, now: datetime | None = None) -> bool:
        if self.daily <= 0 or self.monthly <= 0:
            return False
        current = now or datetime.now(UTC)
        buckets = (
            ("day", current.strftime("%Y-%m-%d"), self.daily),
            ("month", current.strftime("%Y-%m"), self.monthly),
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Reject links instead of silently following a wrongly configured file.
        if self.path.is_symlink():
            raise OSError("Invalid quota path")
        with (
            closing(sqlite3.connect(self.path, timeout=0.25)) as connection,
            connection,
        ):
            if os.name == "posix":
                self.path.chmod(0o600)
            connection.execute("PRAGMA busy_timeout=250")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS lookup_usage (kind TEXT NOT NULL, bucket TEXT NOT NULL, calls INTEGER NOT NULL, PRIMARY KEY(kind,bucket))"
            )
            for kind, bucket, cap in buckets:
                row = connection.execute(
                    "SELECT calls FROM lookup_usage WHERE kind=? AND bucket=?",
                    (kind, bucket),
                ).fetchone()
                if row and row[0] >= cap:
                    return False
            for kind, bucket, _ in buckets:
                connection.execute(
                    "INSERT INTO lookup_usage VALUES (?,?,1) ON CONFLICT(kind,bucket) DO UPDATE SET calls=calls+1",
                    (kind, bucket),
                )
            # Bound retained metadata to the current UTC day and month.
            connection.execute(
                "DELETE FROM lookup_usage WHERE (kind='day' AND bucket<>?) OR (kind='month' AND bucket<>?)",
                (buckets[0][1], buckets[1][1]),
            )
        return True


def _lookup(url: str, key: str) -> dict[str, object]:
    """Run only in the killable child. Never return remote diagnostic text."""
    params = [("threatTypes", value) for value in THREAT_TYPES] + [("uri", url)]
    try:
        with requests.Session() as session:
            session.trust_env = False
            with session.get(
                API_URL,
                params=params,
                headers={"x-goog-api-key": key},
                timeout=(2, 3),
                allow_redirects=False,
                stream=True,
            ) as response:
                if response.status_code != 200:
                    return {
                        "error": "provider_http_error",
                        "status_code": response.status_code,
                    }
                body = bytearray()
                for part in response.iter_content(chunk_size=8192):
                    body.extend(part)
                    if len(body) > MAX_RESPONSE_BYTES:
                        return {"error": "provider_response_limit"}
                value = json.loads(body)
                if not isinstance(value, dict):
                    raise TypeError
                if value == {}:
                    return {"threat_types": []}
                threat = value.get("threat")
                if not isinstance(threat, dict):
                    raise TypeError
                types = threat.get("threatTypes")
                expiry = threat.get("expireTime")
                if (
                    not isinstance(types, list)
                    or not types
                    or any(item not in THREAT_TYPES for item in types)
                    or not isinstance(expiry, str)
                ):
                    raise ValueError
                expires = datetime.fromisoformat(expiry)
                if expires.tzinfo is None or expires <= datetime.now(UTC):
                    raise ValueError
                return {
                    "threat_types": list(dict.fromkeys(types)),
                    "expire_time": expires.isoformat(),
                }
    except (requests.RequestException, ValueError, TypeError, UnicodeError):
        return {"error": "provider_request_failed"}


def worker_main() -> None:
    os.umask(0o077)
    if os.name == "posix":
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (5, 6))
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
        resource.setrlimit(
            resource.RLIMIT_FSIZE, (MAX_RESPONSE_BYTES, MAX_RESPONSE_BYTES)
        )
    try:
        raw = sys.stdin.buffer.read(8193)
        job = json.loads(raw)
        if (
            len(raw) > 8192
            or not isinstance(job["url"], str)
            or not 1 <= len(job["url"]) <= 2048
            or not isinstance(job["key"], str)
            or not 1 <= len(job["key"]) <= 512
        ):
            raise ValueError
        from app.services.url_safety import validate_public_http_url

        # Privacy guard as well as fetch safety: never disclose an internal URL
        # to Google even if this scanner is invoked outside the default pipeline.
        if not validate_public_http_url(job["url"]).is_safe:
            value = {"error": "ineligible_url"}
        else:
            value = _lookup(job["url"], job["key"])
    except Exception:  # noqa: BLE001 - child process diagnostics must remain redacted.
        value = {"error": "provider_worker_failed"}
    sys.stdout.buffer.write(json.dumps(value, allow_nan=False).encode())


class GoogleWebRiskScanner(BaseScanner):
    THREAT_TYPES = THREAT_TYPES

    def __init__(
        self,
        api_key: str | None = None,
        *,
        allow_url_sharing: bool = False,
        quota_path: str | Path | None = None,
        daily_limit: int = 1000,
        monthly_limit: int = 20000,
        allow_query_urls: bool = False,
    ) -> None:
        super().__init__(name="GoogleWebRisk")
        self.api_key = (api_key or "").strip() or None
        self.allow_url_sharing = allow_url_sharing
        self.allow_query_urls = allow_query_urls
        self.quota = LookupQuota(
            quota_path or BACKEND_ROOT / "data" / "web-risk-usage.sqlite3",
            daily_limit,
            monthly_limit,
        )

    def _missing(
        self, code: str, *, failed: bool = False, **details: object
    ) -> StageResult:
        return StageResult(
            scanner=self.name,
            verdict="unknown",
            status="failed" if failed else "unavailable",
            reason="Web Risk lookup did not complete",
            details={"error": code, **details},
        )

    def scan(self, url: str) -> StageResult:
        if not self.api_key:
            return self._missing("provider_key_missing")
        if not self.allow_url_sharing:
            return self._missing("url_sharing_not_enabled")
        try:
            parsed = urlsplit(url)
            if (
                len(url) > 2048
                or parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
            ):
                return self._missing("ineligible_url")
            host = parsed.hostname.lower().rstrip(".")
            if "." not in host or host.endswith(
                (".localhost", ".local", ".internal", ".test", ".example", ".invalid")
            ):
                return self._missing("ineligible_url")
            try:
                from app.services.url_safety import _is_blocked_ip

                if _is_blocked_ip(ipaddress.ip_address(host)):
                    return self._missing("ineligible_url")
            except ValueError:
                pass
            if parsed.query and not self.allow_query_urls:
                return self._missing("query_url_sharing_disabled")
            # Fragments are not sent to the HTTP server or this provider.
            eligible = parsed._replace(fragment="").geturl()
            code = f"import sys; sys.path.insert(0, {str(BACKEND_ROOT)!r}); from app.services.web_risk_scanner import worker_main; worker_main()"
            budget = _budget.get() or LookupBudget()
            with budget.call() as seconds:
                if not self.quota.reserve():
                    return self._missing("provider_local_quota_exhausted")
                raw = bounded_process(
                    [sys.executable, "-I", "-c", code],
                    json.dumps({"url": eligible, "key": self.api_key}).encode(),
                    seconds,
                )
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise TypeError
            if data.get("error"):
                # Only locally defined codes and integer status can leave here.
                status = data.get("status_code")
                return self._missing(
                    "provider_lookup_failed",
                    failed=True,
                    **({"status_code": status} if type(status) is int else {}),
                )
            types = data["threat_types"]
            if not isinstance(types, list) or any(
                value not in THREAT_TYPES for value in types
            ):
                raise ValueError
            if not types:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    reason="No Web Risk list match",
                    details={"matches": 0},
                )
            expiry = datetime.fromisoformat(str(data["expire_time"]))
            if expiry.tzinfo is None or expiry <= datetime.now(UTC):
                raise ValueError
            return StageResult(
                scanner=self.name,
                verdict="malicious",
                risk_score=0.97,
                reason="URL matched a Web Risk threat list",
                details={"threat_types": types, "expire_time": expiry.isoformat()},
            )
        except WorkerFailure as exc:
            return self._missing(
                exc.code, failed=exc.code != "lookup_scan_budget_exhausted"
            )
        except (OSError, sqlite3.Error, ValueError, KeyError, TypeError, UnicodeError):
            return self._missing("provider_lookup_failed", failed=True)
