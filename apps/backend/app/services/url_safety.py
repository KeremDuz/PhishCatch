from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket
from urllib.parse import urlparse

from app.utils.url_utils import parse_url_parts


@dataclass(frozen=True)
class UrlSafetyResult:
    is_safe: bool
    reason: str | None = None
    details: dict[str, object] | None = None


def validate_public_http_url(url: str) -> UrlSafetyResult:
    try:
        parsed = urlparse(url)
        # Accessing .port also rejects malformed/out-of-range authorities.
        if parsed.port == 0:
            return UrlSafetyResult(is_safe=False, reason="URL port is invalid")
    except ValueError:
        return UrlSafetyResult(is_safe=False, reason="URL authority is invalid")

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

    try:
        url_parts = parse_url_parts(url)
        hostname = url_parts.ascii_hostname
    except Exception:
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
    # is_private alone does not cover CGNAT (100.64/10, including Tailscale).
    # Multicast can be is_global on some Python versions; reject it explicitly.
    if not ip_address.is_global or ip_address.is_reserved or ip_address.is_multicast:
        return True
    # Reject IPv6 transition addresses rather than letting an encoded IPv4
    # destination bypass the policy or depend on the host's routing setup.
    if isinstance(ip_address, ipaddress.IPv6Address):
        return (
            ip_address.ipv4_mapped is not None
            or ip_address.sixtofour is not None
            or ip_address.teredo is not None
        )
    return False
