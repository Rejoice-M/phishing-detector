"""
The analyzer holds five checks that need no internet lookups. 
It flags HTTP instead of HTTPS, a raw IP address instead of a domain name, an unusually long URL, 
too many subdomains (like login.secure.account.paypal.example.com, which hides the real domain), 
and the @ trick (google.com@evil.com, where the real host is whatever comes after the @). Each check 
returns a Finding with a point value and a plain-English reason.
"""
import ipaddress
from dataclasses import dataclass
from urllib.parse import ParseResult, urlparse

import tldextract

# Use the bundled public suffix list so no network call is needed
_extract = tldextract.TLDExtract(suffix_list_urls=())

MAX_URL_LENGTH = 75
MAX_SUBDOMAINS = 2


@dataclass
class Finding:
    check: str
    triggered: bool
    points: int
    reason: str


def _parse(url: str) -> ParseResult:
    url = url.strip()
    if "://" not in url:
        url = "//" + url  # lets urlparse treat the host correctly
    return urlparse(url)


def check_https(parsed: ParseResult) -> Finding:
    if parsed.scheme == "":
        return Finding("https", False, 0, "No scheme given, so HTTPS could not be checked")
    if parsed.scheme == "http":
        return Finding("https", True, 20, "URL uses HTTP, so the connection is not encrypted")
    return Finding("https", False, 0, "URL uses HTTPS")


def check_ip_address(parsed: ParseResult) -> Finding:
    host = parsed.hostname
    if host:
        try:
            ipaddress.ip_address(host)
            return Finding("ip_address", True, 35, "URL uses a raw IP address instead of a domain name")
        except ValueError:
            pass
    return Finding("ip_address", False, 0, "URL uses a domain name")


def check_length(url: str) -> Finding:
    length = len(url.strip())
    if length > MAX_URL_LENGTH:
        return Finding("length", True, 10, f"URL is unusually long ({length} characters)")
    return Finding("length", False, 0, f"URL length is normal ({length} characters)")


def check_subdomains(parsed: ParseResult) -> Finding:
    host = parsed.hostname or ""
    subdomain = _extract(host).subdomain
    count = len(subdomain.split(".")) if subdomain else 0
    if count > MAX_SUBDOMAINS:
        return Finding("subdomains", True, 15, f"URL has {count} subdomain levels, which can hide the real domain")
    return Finding("subdomains", False, 0, f"Subdomain count is normal ({count})")


def check_at_symbol(parsed: ParseResult) -> Finding:
    if parsed.username is not None:
        return Finding("at_symbol", True, 25, "URL contains '@', so text before it is ignored and the real host is after it")
    return Finding("at_symbol", False, 0, "No '@' trick in the URL")


def analyze_url(url: str) -> list[Finding]:
    parsed = _parse(url)
    return [
        check_https(parsed),
        check_ip_address(parsed),
        check_length(url),
        check_subdomains(parsed),
        check_at_symbol(parsed),
    ]
