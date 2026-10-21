"""Free hostname-only Cloudflare security DNS context, not a URL scanner.

No user URL is submitted to Radar or published. Sinkholes/filters are review
signals, never proof of phishing. DNS addresses are not used to fetch a page.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import time
from urllib.parse import urlsplit

import requests

from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner
from app.services.reputation_budget import LookupBudget, _budget
from app.services.worker_process import BACKEND_ROOT, WorkerFailure, bounded_process

SECURITY_ENDPOINT = "https://security.cloudflare-dns.com/dns-query"
CONTROL_ENDPOINT = "https://cloudflare-dns.com/dns-query"
MAX_DNS_RESPONSE = 64 * 1024


def public_hostname(url: str) -> str | None:
    parts = urlsplit(url)
    if (
        parts.scheme not in {"http", "https"}
        or parts.username is not None
        or parts.password is not None
    ):
        return None
    host = (parts.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
    try:
        ipaddress.ip_address(host)
        return None  # Literal addresses do not have a domain reputation here.
    except ValueError:
        pass
    if (
        len(host) > 253
        or "." not in host
        or host.endswith(
            (
                ".localhost",
                ".local",
                ".internal",
                ".test",
                ".example",
                ".invalid",
                ".home.arpa",
            )
        )
        or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.split(".")
        )
    ):
        return None
    return host


def _dns_query(endpoint: str, hostname: str) -> dict[str, object]:
    if endpoint not in {SECURITY_ENDPOINT, CONTROL_ENDPOINT}:
        raise ValueError("Invalid resolver")
    with requests.Session() as session:
        session.trust_env = False
        with session.get(
            endpoint,
            params={"name": hostname, "type": "A"},
            headers={"Accept": "application/dns-json"},
            allow_redirects=False,
            stream=True,
            timeout=(2, 2),
        ) as response:
            if response.status_code != 200:
                raise ValueError("Resolver unavailable")
            body = bytearray()
            for chunk in response.iter_content(8192):
                body.extend(chunk)
                if len(body) > MAX_DNS_RESPONSE:
                    raise ValueError("Resolver body limit")
            data = json.loads(body)
    if (
        not isinstance(data, dict)
        or type(data.get("Status")) is not int
        or data.get("TC") is not False
    ):
        raise ValueError("Invalid DNS response")
    question = data.get("Question")
    if (
        not isinstance(question, list)
        or len(question) != 1
        or question[0].get("name", "").lower().rstrip(".") != hostname
        or type(question[0].get("type")) is not int
        or question[0].get("type") != 1
    ):
        raise ValueError("Mismatched DNS question")
    if data["Status"] not in {0, 3}:
        raise ValueError("DNS lookup did not complete")
    answers = data.get("Answer", [])
    if not isinstance(answers, list) or len(answers) > 128:
        raise ValueError("Invalid DNS answer")
    for row in answers:
        if not isinstance(row, dict):
            raise TypeError("Invalid DNS record")
        if (
            type(row.get("type")) is not int
            or type(row.get("TTL")) is not int
            or not 0 <= row["TTL"] <= 4294967295
            or not isinstance(row.get("name"), str)
            or not isinstance(row.get("data"), str)
        ):
            raise ValueError("Invalid DNS record fields")
    if data["Status"] == 3 and answers:
        raise ValueError("Contradictory DNS response")
    # Follow only the queried name's CNAME chain, never unrelated records.
    names = {hostname}
    current_name = hostname
    for _ in range(16):
        added = {
            str(row.get("data", "")).lower().rstrip(".")
            for row in answers
            if isinstance(row, dict)
            and row.get("type") == 5
            and str(row.get("name", "")).lower().rstrip(".") == current_name
        }
        if not added:
            break
        if len(added) != 1 or added & names:
            raise ValueError("Invalid CNAME chain")
        names |= added
        current_name = next(iter(added))
    else:
        if any(
            row["type"] == 5 and row["name"].lower().rstrip(".") == current_name
            for row in answers
        ):
            raise ValueError("CNAME chain exceeds limit")
    addresses: list[str] = []
    ttls: list[int] = []
    for row in answers:
        if not isinstance(row, dict):
            raise TypeError("Invalid DNS record")
        if str(row.get("name", "")).lower().rstrip(".") not in names:
            continue
        if type(row.get("TTL")) is int:
            ttls.append(max(0, row["TTL"]))
        if row.get("type") == 1:
            addresses.append(str(ipaddress.IPv4Address(row["data"])))
    comments = data.get("Comment", [])
    if not isinstance(comments, list) or any(
        not isinstance(value, str) for value in comments
    ):
        raise ValueError("Invalid DNS metadata")
    codes = sorted(
        {
            int(match.group(1))
            for value in comments
            if (match := re.match(r"EDE\((\d{1,5})\):", value))
        }
    )
    return {
        "addresses": addresses,
        "ttl": min(ttls, default=0),
        "ede_codes": codes,
        "nxdomain": data["Status"] == 3,
    }


def query_security_dns(hostname: str) -> dict[str, object]:
    try:
        security = _dns_query(SECURITY_ENDPOINT, hostname)
        addresses = security["addresses"]
        zero = bool(addresses) and set(addresses) == {"0.0.0.0"}
        control_public = False
        if zero:
            control = _dns_query(CONTROL_ENDPOINT, hostname)
            security["ttl"] = min(int(security["ttl"]), int(control["ttl"]))
            control_public = any(
                ipaddress.ip_address(address).is_global
                for address in control["addresses"]
            )
        return {
            "filtered": zero and control_public,
            "ambiguous_sinkhole": zero and not control_public,
            "policy_filter": bool(set(security["ede_codes"]) & {15, 16, 17}),
            "ede_codes": security["ede_codes"],
            "nxdomain": security["nxdomain"],
            "provider_cache_ttl_seconds": min(300, int(security["ttl"])),
        }
    except (
        requests.RequestException,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        UnicodeError,
    ):
        return {"error": "dns_security_lookup_failed"}


def worker_main() -> None:
    os.umask(0o077)
    if os.name == "posix":
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (4, 5))
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_DNS_RESPONSE, MAX_DNS_RESPONSE))
    try:
        raw = sys.stdin.buffer.read(1025)
        value = json.loads(raw)
        host = value["hostname"]
        if (
            len(raw) > 1024
            or not isinstance(host, str)
            or public_hostname("https://" + host + "/") != host
        ):
            raise ValueError
        result = query_security_dns(host)
    except Exception:  # noqa: BLE001 - redact child diagnostics.
        result = {"error": "dns_security_worker_failed"}
    sys.stdout.buffer.write(json.dumps(result, allow_nan=False).encode())


class CloudflareDnsSecurityScanner(BaseScanner):
    def __init__(self) -> None:
        super().__init__(name="CloudflareDnsSecurity")

    def scan(self, url: str) -> StageResult:
        hostname: str | None = None
        try:
            hostname = public_hostname(url)
            if hostname is None:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    reason="Domain DNS security check is not applicable to this target",
                    details={"not_applicable": True},
                )
            budget = _budget.get() or LookupBudget()
            remembered = budget.domain_results.get(hostname)
            if remembered and remembered[0] > time.monotonic():
                return remembered[1].model_copy(deep=True)
            with budget.call() as seconds:
                code = f"import sys; sys.path.insert(0, {str(BACKEND_ROOT)!r}); from app.services.cloudflare_dns_scanner import worker_main; worker_main()"
                raw = bounded_process(
                    [sys.executable, "-I", "-c", code],
                    json.dumps({"hostname": hostname}).encode(),
                    min(seconds, 5.0),
                )
            data = json.loads(raw)
            if not isinstance(data, dict) or data.get("error"):
                raise ValueError
            if (
                type(data.get("filtered")) is not bool
                or type(data.get("ambiguous_sinkhole")) is not bool
            ):
                raise ValueError
            policy_filter = data.get("policy_filter", False)
            if type(policy_filter) is not bool:
                raise ValueError("Invalid DNS filter flag")
            review = data["filtered"] or data["ambiguous_sinkhole"] or policy_filter
            ttl = data.get("provider_cache_ttl_seconds")
            if type(ttl) is not int or not 0 <= ttl <= 300:
                raise ValueError
            result = StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=0.0,
                reason="Security DNS filter requires review"
                if review
                else "No security DNS filter match; this does not establish URL safety",
                details={
                    "requires_review": review,
                    "filtered": data["filtered"],
                    "ambiguous_sinkhole": data["ambiguous_sinkhole"],
                    "policy_filter": policy_filter,
                    "scope": "hostname_only",
                    "provider_cache_ttl_seconds": ttl,
                },
            )
            if ttl > 0:
                budget.domain_results[hostname] = (
                    time.monotonic() + ttl,
                    result.model_copy(deep=True),
                )
            return result
        except WorkerFailure as exc:
            error = exc.code
        except (ValueError, TypeError, KeyError, UnicodeError):
            error = "dns_security_lookup_failed"
        result = StageResult(
            scanner=self.name,
            verdict="unknown",
            status="unavailable",
            reason="Security DNS check did not complete",
            details={"error": error},
        )
        budget = _budget.get()
        if hostname and budget is not None:
            # Retry on the next scan, not again for each path in this scan.
            # This memo is destroyed when the analysis context exits.
            budget.domain_results[hostname] = (
                float("inf"),
                result.model_copy(deep=True),
            )
        return result
