from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket
from urllib.parse import urlparse


@dataclass(frozen=True)
class UrlSafetyResult:
    is_safe: bool
    reason: str | None = None
    details: dict[str, object] | None = None


def validate_public_http_url(url: str) -> UrlSafetyResult:
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        return UrlSafetyResult(
            is_safe=False,
            reason="Only http and https URLs can be fetched",
            details={"scheme": parsed.scheme},
        )

    if not parsed.hostname:
        return UrlSafetyResult(
            is_safe=False,
            reason="URL does not include a hostname",
            details={"url": url},
        )

    if parsed.username or parsed.password:
        return UrlSafetyResult(
            is_safe=False,
            reason="URLs with embedded credentials are not fetched",
            details={"hostname": parsed.hostname},
        )

    hostname = parsed.hostname.strip().lower()
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".localhost"):
        return UrlSafetyResult(
            is_safe=False,
            reason="Localhost URLs are not fetched",
            details={"hostname": hostname},
        )

    resolved_ips = _resolve_hostname(hostname)
    if not resolved_ips:
        return UrlSafetyResult(
            is_safe=False,
            reason="Hostname could not be resolved",
            details={"hostname": hostname},
        )

    blocked_ips = [ip for ip in resolved_ips if _is_blocked_ip(ip)]
    if blocked_ips:
        return UrlSafetyResult(
            is_safe=False,
            reason="Hostname resolves to a non-public IP address",
            details={"hostname": hostname, "blocked_ips": [str(ip) for ip in blocked_ips]},
        )

    return UrlSafetyResult(
        is_safe=True,
        details={"hostname": hostname, "resolved_ips": [str(ip) for ip in resolved_ips]},
    )


def _resolve_hostname(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        return [ipaddress.ip_address(hostname)]
    except ValueError:
        pass

    try:
        address_info = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []

    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for family, _type, _proto, _canonname, sockaddr in address_info:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        try:
            ips.append(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue

    return sorted(set(ips), key=str)


def _is_blocked_ip(ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(
        [
            ip_address.is_private,
            ip_address.is_loopback,
            ip_address.is_link_local,
            ip_address.is_multicast,
            ip_address.is_reserved,
            ip_address.is_unspecified,
        ]
    )
