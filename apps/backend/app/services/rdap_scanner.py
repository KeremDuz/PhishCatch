"""Optional registration context; never evidence that a URL is clean."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from urllib.parse import urlsplit

from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner
from app.services.page_fetch import _fetch_page
from app.services.worker_process import WorkerFailure, run_worker
from app.utils.url_utils import is_ip_hostname, parse_url_parts


def registration_context(url: str) -> dict[str, object]:
    domain = parse_url_parts(url).registrable_domain
    if not domain or is_ip_hostname(domain):
        return {"available": False}
    bootstrap = _fetch_page("https://data.iana.org/rdap/dns.json", None)
    if bootstrap.status_code != 200:
        return {"available": False}
    services = json.loads(bootstrap.body).get("services", [])
    tld = domain.rsplit(".", 1)[-1]
    for suffixes, urls in services:
        if tld not in suffixes:
            continue
        endpoint = next(
            (base for base in urls if urlsplit(base).scheme == "https"), None
        )
        if not endpoint:
            break
        page = _fetch_page(endpoint.rstrip("/") + "/domain/" + domain, None)
        if page.status_code != 200:
            break
        record = json.loads(page.body)
        if str(record.get("ldhName", "")).lower().strip(".") != domain.lower():
            break
        for event in record.get("events", []):
            if event.get("eventAction") != "registration":
                continue
            created = datetime.fromisoformat(event["eventDate"])
            if created.tzinfo is None:
                break
            age = (datetime.now(UTC) - created).days
            if age < 0:
                break
            return {
                "available": True,
                "domain": domain,
                "age_days": age,
                "creation_date": created.isoformat(),
                "signal": "new_domain" if age < 30 else "established_domain",
            }
        break
    return {"available": False, "domain": domain}


class RdapScanner(BaseScanner):
    def __init__(self) -> None:
        super().__init__(name="RdapScanner")

    def scan(self, url: str) -> StageResult:
        try:
            info = run_worker("rdap", {"url": url}, timeout=10)
        except (WorkerFailure, ValueError, TypeError):
            info = {"available": False}
        # Context is explicitly optional in the declared detection profile.
        # Missing dates do not claim a clean verdict or complete registration lookup.
        return StageResult(
            scanner=self.name,
            verdict="unknown",
            risk_score=0.15 if info.get("signal") == "new_domain" else 0,
            reason="Recent domain registration"
            if info.get("signal") == "new_domain"
            else "Optional RDAP registration context",
            details={**info, "optional_context": True},
        )
