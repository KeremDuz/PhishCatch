import datetime
import ipaddress
from urllib.parse import urlparse

from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner


class WhoisScanner(BaseScanner):
    def __init__(self) -> None:
        super().__init__(name="WhoisScanner")
        # Phishing domains usually < 30 days old
        self.suspicious_days = 30

    def scan(self, url: str) -> StageResult:
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ""

            try:
                ipaddress.ip_address(domain)
                is_ip_address = True
            except ValueError:
                is_ip_address = False

            if not domain or is_ip_address:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    confidence=0.6,
                    risk_score=0.55,
                    reason="Direct IP address used instead of domain",
                    details={"domain": domain, "signal": "direct_ip"},
                )

            # Use subprocess to run whois command natively with timeout
            import subprocess
            try:
                result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=3)
                creation_date = None
                for line in result.stdout.splitlines():
                    if "Creation Date" in line or "Created On" in line:
                        # naive extraction
                        date_str = line.split(":", 1)[1].strip()
                        from dateutil.parser import parse
                        try:
                            creation_date = parse(date_str, fuzzy=True)
                        except Exception:
                            pass
                        break
            except subprocess.TimeoutExpired:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    risk_score=0.0,
                    reason="WHOIS lookup timed out",
                    details={"domain": domain},
                )

            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if not creation_date:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    risk_score=0.0,
                    reason="Domain creation date not found",
                    details={"domain": domain},
                )
            
            # timezone bilgisini temizle
            creation_date = creation_date.replace(tzinfo=None)
            
            age_days = (datetime.datetime.now().replace(tzinfo=None) - creation_date).days
            
            if age_days < self.suspicious_days:
                risk_score = max(0.3, 0.55 - (age_days / self.suspicious_days * 0.25))
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    confidence=max(0.6, 1.0 - (age_days / self.suspicious_days)),
                    risk_score=round(risk_score, 4),
                    reason=f"Domain is very new (created {age_days} days ago)",
                    details={
                        "domain": domain,
                        "age_days": age_days,
                        "creation_date": str(creation_date),
                        "signal": "new_domain",
                    },
                )
            else:
                return StageResult(
                    scanner=self.name,
                    verdict="clean",
                    risk_score=0.0,
                    reason=f"Domain is established ({age_days} days old)",
                    details={
                        "domain": domain,
                        "age_days": age_days,
                        "creation_date": str(creation_date),
                        "signal": "established_domain",
                    },
                )
        except Exception as e:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=0.0,
                reason="Failed to execute WHOIS lookup",
                details={"error": str(e)},
            )
