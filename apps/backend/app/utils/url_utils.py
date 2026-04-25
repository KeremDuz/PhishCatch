from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from urllib.parse import SplitResult, urlsplit, urlunsplit


try:
    import tldextract
except Exception:  # pragma: no cover - optional production dependency
    tldextract = None


_TLD_EXTRACTOR = (
    tldextract.TLDExtract(suffix_list_urls=()) if tldextract is not None else None
)


KNOWN_MULTI_PART_SUFFIXES = {
    "ac.uk",
    "co.jp",
    "co.uk",
    "com.ar",
    "com.au",
    "com.br",
    "com.mx",
    "com.py",
    "com.tr",
    "edu.tr",
    "gov.tr",
    "net.tr",
    "org.uk",
    "org.tr",
    "github.io",
    "pages.dev",
    "workers.dev",
    "vercel.app",
    "netlify.app",
    "webflow.io",
    "weebly.com",
    "framer.app",
    "blogspot.com",
}


CONFUSABLE_CHAR_MAP = str.maketrans(
    {
        # Cyrillic
        "\u0430": "a",
        "\u0410": "A",
        "\u0435": "e",
        "\u0415": "E",
        "\u043e": "o",
        "\u041e": "O",
        "\u0440": "p",
        "\u0420": "P",
        "\u0441": "c",
        "\u0421": "C",
        "\u0445": "x",
        "\u0425": "X",
        "\u0443": "y",
        "\u0423": "Y",
        "\u0456": "i",
        "\u0406": "I",
        "\u0458": "j",
        "\u0408": "J",
        "\u04cf": "l",
        "\u0412": "B",
        "\u041d": "H",
        "\u041a": "K",
        "\u041c": "M",
        "\u0422": "T",
        "\u0432": "b",
        "\u043d": "h",
        "\u043a": "k",
        "\u043c": "m",
        "\u0442": "t",
        # Greek
        "\u03b1": "a",
        "\u0391": "A",
        "\u03bf": "o",
        "\u039f": "O",
        "\u03c1": "p",
        "\u03a1": "P",
        "\u03bd": "v",
        "\u039d": "N",
        "\u03c7": "x",
        "\u03a7": "X",
        "\u03b9": "i",
        "\u0399": "I",
        "\u03ba": "k",
        "\u039a": "K",
        "\u03bc": "m",
        "\u039c": "M",
        "\u03c4": "t",
        "\u03a4": "T",
    }
)


@dataclass(frozen=True)
class UrlParts:
    url: str
    scheme: str
    hostname: str
    ascii_hostname: str
    unicode_hostname: str
    normalized_hostname: str
    registrable_domain: str
    domain_label: str
    suffix: str
    subdomain: str
    path: str
    query: str
    fragment: str
    is_idn: bool
    has_punycode_label: bool
    has_mixed_script: bool
    skeleton_hostname: str


def ensure_http_url(url: str) -> str:
    candidate = str(url).strip()
    if not candidate.startswith(("http://", "https://")):
        candidate = f"https://{candidate}"
    return candidate


def canonicalize_url(url: str) -> str:
    parsed = urlsplit(ensure_http_url(url))
    hostname = _normalize_hostname(parsed.hostname or "")
    ascii_hostname = _to_ascii_hostname(hostname)
    netloc = _build_netloc(parsed, ascii_hostname)
    path = parsed.path or ""
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, parsed.fragment))


def parse_url_parts(url: str) -> UrlParts:
    canonical = canonicalize_url(url)
    parsed = urlsplit(canonical)
    hostname = _normalize_hostname(parsed.hostname or "")
    unicode_hostname = _to_unicode_hostname(hostname)
    ascii_hostname = _to_ascii_hostname(unicode_hostname)
    registrable_domain, domain_label, suffix, subdomain = _extract_domain_parts(ascii_hostname)
    scripts = _hostname_scripts(unicode_hostname)

    return UrlParts(
        url=canonical,
        scheme=parsed.scheme.lower(),
        hostname=hostname,
        ascii_hostname=ascii_hostname,
        unicode_hostname=unicode_hostname,
        normalized_hostname=unicode_hostname.lower(),
        registrable_domain=registrable_domain,
        domain_label=domain_label,
        suffix=suffix,
        subdomain=subdomain,
        path=parsed.path or "",
        query=parsed.query or "",
        fragment=parsed.fragment or "",
        is_idn=ascii_hostname != unicode_hostname.lower(),
        has_punycode_label=any(label.startswith("xn--") for label in ascii_hostname.split(".")),
        has_mixed_script=len(scripts) > 1,
        skeleton_hostname=confusable_skeleton(unicode_hostname.lower()),
    )


def confusable_skeleton(value: str) -> str:
    return value.translate(CONFUSABLE_CHAR_MAP)


def hostname_matches_allowed(hostname: str, allowed_hosts: set[str]) -> bool:
    try:
        parts = parse_url_parts(f"https://{hostname}")
        candidates = {
            parts.ascii_hostname,
            parts.unicode_hostname.lower(),
            parts.registrable_domain,
        }
    except ValueError:
        candidates = {hostname.lower().strip(".")}

    for candidate in candidates:
        for allowed in allowed_hosts:
            allowed = allowed.lower().strip(".")
            if candidate == allowed or candidate.endswith(f".{allowed}"):
                return True
    return False


def is_ip_hostname(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def _normalize_hostname(hostname: str) -> str:
    return hostname.strip().strip(".").lower()


def _to_ascii_hostname(hostname: str) -> str:
    labels = [label for label in hostname.split(".") if label]
    ascii_labels: list[str] = []
    for label in labels:
        try:
            ascii_labels.append(label.encode("idna").decode("ascii").lower())
        except UnicodeError:
            ascii_labels.append(label.lower())
    return ".".join(ascii_labels)


def _to_unicode_hostname(hostname: str) -> str:
    labels = [label for label in hostname.split(".") if label]
    unicode_labels: list[str] = []
    for label in labels:
        try:
            unicode_labels.append(label.encode("ascii").decode("idna").lower())
        except UnicodeError:
            unicode_labels.append(label.lower())
    return ".".join(unicode_labels)


def _build_netloc(parsed: SplitResult, ascii_hostname: str) -> str:
    credentials = ""
    if parsed.username:
        credentials = parsed.username
        if parsed.password:
            credentials = f"{credentials}:{parsed.password}"
        credentials = f"{credentials}@"

    host = ascii_hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    port = ""
    if parsed.port and not _is_default_port(parsed.scheme.lower(), parsed.port):
        port = f":{parsed.port}"

    return f"{credentials}{host}{port}"


def _is_default_port(scheme: str, port: int) -> bool:
    return (scheme == "http" and port == 80) or (scheme == "https" and port == 443)


def _extract_domain_parts(hostname: str) -> tuple[str, str, str, str]:
    if not hostname or is_ip_hostname(hostname):
        return hostname, hostname, "", ""

    if _TLD_EXTRACTOR is not None:
        extracted = _TLD_EXTRACTOR(hostname)
        if extracted.domain and extracted.suffix:
            registrable = f"{extracted.domain}.{extracted.suffix}"
            return registrable, extracted.domain, extracted.suffix, extracted.subdomain

    labels = [label for label in hostname.split(".") if label]
    if len(labels) <= 1:
        return hostname, hostname, "", ""

    suffix_length = 1
    for length in range(min(3, len(labels) - 1), 1, -1):
        suffix_candidate = ".".join(labels[-length:])
        if suffix_candidate in KNOWN_MULTI_PART_SUFFIXES:
            suffix_length = length
            break

    domain_index = len(labels) - suffix_length - 1
    if domain_index < 0:
        return hostname, labels[0], ".".join(labels[1:]), ""

    suffix = ".".join(labels[-suffix_length:])
    domain_label = labels[domain_index]
    registrable = ".".join(labels[domain_index:])
    subdomain = ".".join(labels[:domain_index])
    return registrable, domain_label, suffix, subdomain


def _hostname_scripts(hostname: str) -> set[str]:
    scripts: set[str] = set()
    for character in hostname:
        if not character.isalpha():
            continue
        codepoint = ord(character)
        if "a" <= character.lower() <= "z":
            scripts.add("latin")
        elif 0x0370 <= codepoint <= 0x03FF:
            scripts.add("greek")
        elif 0x0400 <= codepoint <= 0x052F:
            scripts.add("cyrillic")
        elif re.match(r"[^\W\d_]", character, re.UNICODE):
            scripts.add("other")
    return scripts
