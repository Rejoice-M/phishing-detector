# url_analyzer.py
# Purpose: looks at a URL and runs a series of phishing checks on it.
# Each check returns a Finding (check name, triggered yes/no, points, plain-English reason).
#
# Offline checks (no internet needed):
#   1. HTTPS         - flags plain HTTP (the connection is not encrypted)
#   2. IP address    - flags a raw IP address used instead of a domain name
#   3. Length        - flags unusually long URLs
#   4. Subdomains    - flags too many subdomain levels, which can hide the real domain
#                      (e.g. login.secure.account.paypal.example.com)
#   5. @ symbol      - flags the '@' trick (google.com@evil.com really goes to evil.com)
#   6. Typosquatting - flags lookalikes of known brands (paypa1.com) and brand names hidden
#                      in the domain or a subdomain; uses the LEGIT_DOMAINS list
#
# Network checks (skipped when include_network=False):
#   7. Domain age    - looks up WHOIS and flags newly registered domains
#   8. Safe Browsing - asks Google whether the URL is on its phishing/malware blacklists
#                      (needs SAFE_BROWSING_API_KEY in .env, skipped if it is missing)
#
# analyze_url() runs them all and returns the list of findings.
# The tests pass include_network=False so they never touch the internet.

import ipaddress
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import ParseResult, urlparse

import requests
import tldextract
import whois
from dotenv import load_dotenv

load_dotenv()  # reads SAFE_BROWSING_API_KEY from the .env file

# Use the bundled public suffix list so no network call is needed
_extract = tldextract.TLDExtract(suffix_list_urls=())

MAX_URL_LENGTH = 75
MAX_SUBDOMAINS = 2

SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_THREAT_NAMES = {
    "MALWARE": "malware",
    "SOCIAL_ENGINEERING": "phishing / social engineering",
    "UNWANTED_SOFTWARE": "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "a potentially harmful application",
}

# Small starter list of brands that phishers commonly imitate.
# Add more over time (especially South African ones).
LEGIT_DOMAINS = {
    "google.com", "google.co.za", "gmail.com", "youtube.com",
    "facebook.com", "instagram.com", "whatsapp.com",
    "microsoft.com", "outlook.com",
    "apple.com", "icloud.com", "amazon.com", "netflix.com",
    "paypal.com", "linkedin.com", "twitter.com", "dropbox.com", "ebay.com",
    "fnb.co.za", "absa.co.za", "standardbank.co.za", "nedbank.co.za",
    "capitecbank.co.za", "takealot.com", "sars.gov.za",
}
_BRANDS = sorted({d.split(".")[0] for d in LEGIT_DOMAINS})

# Characters attackers swap in to imitate letters (0 for o, 1 for l, rn for m...)
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"})


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
        return Finding("https", True, 10, "URL uses HTTP, so the connection is not encrypted")
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


# ---------- Typosquatting ----------

def _normalize(label: str) -> str:
    """Undo common lookalike tricks: paypa1 -> paypal, rnicrosoft -> microsoft."""
    label = label.lower().replace("vv", "w").replace("rn", "m")
    return label.translate(_HOMOGLYPHS)


def _edit_distance(a: str, b: str) -> int:
    """Number of single-character edits needed to turn a into b (Levenshtein)."""
    if a == b:
        return 0
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            current.append(min(
                previous[j] + 1,                          # deletion
                current[j - 1] + 1,                       # insertion
                previous[j - 1] + (char_a != char_b),     # substitution
            ))
        previous = current
    return previous[-1]


def check_typosquatting(parsed: ParseResult) -> Finding:
    ext = _extract(parsed.hostname or "")
    domain = ext.top_domain_under_public_suffix
    if not domain:
        return Finding("typosquatting", False, 0, "No registered domain to compare against known brands")
    if domain in LEGIT_DOMAINS:
        return Finding("typosquatting", False, 0, "Domain is a known legitimate brand domain")

    label = ext.domain.lower()

    # 1. Lookalike or exact brand name on an unofficial domain
    for brand in _BRANDS:
        if label == brand:
            return Finding("typosquatting", True, 50,
                           f"Uses the brand name '{brand}' on an unofficial domain ({domain})")
        looks_alike = _normalize(label) == brand
        one_typo = len(brand) >= 5 and len(label) >= 5 and _edit_distance(label, brand) == 1
        if looks_alike or one_typo:
            return Finding("typosquatting", True, 50,
                           f"Domain '{label}' looks like a copy of '{brand}'")

    # 2. Brand name hidden inside the domain (paypal-secure-login.com, paypa1-secure-login.com)
    #    or in a subdomain (paypal.example.com)
    tokens = set()
    if "-" in label:
        tokens.update(label.split("-"))
    for part in ext.subdomain.lower().split("."):
        tokens.update(part.split("-"))
    tokens |= {_normalize(token) for token in tokens}  # also catch lookalike spellings
    for brand in _BRANDS:
        if brand in tokens:
            return Finding("typosquatting", True, 35,
                           f"Brand name '{brand}' appears in a domain that does not belong to it ({domain})")

    return Finding("typosquatting", False, 0, "No lookalike of a known brand detected")


# ---------- Domain age (WHOIS) ----------

def _whois_creation_date(domain: str):
    """Look up when a domain was registered. Returns None if it can't be found."""
    try:
        record = whois.whois(domain)
    except Exception:
        return None

    created = record.creation_date
    if isinstance(created, list):
        created = min((d for d in created if isinstance(d, datetime)), default=None)
    if not isinstance(created, datetime):
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return created


def check_domain_age(parsed: ParseResult, lookup=_whois_creation_date) -> Finding:
    domain = _extract(parsed.hostname or "").top_domain_under_public_suffix
    if not domain:
        return Finding("domain_age", False, 0, "No registered domain to look up")

    created = lookup(domain)
    if created is None:
        return Finding("domain_age", False, 0,
                       "Domain age could not be determined (WHOIS lookup failed or data is hidden)")

    age_days = (datetime.now(timezone.utc) - created).days
    if age_days < 30:
        return Finding("domain_age", True, 30, f"Domain was registered only {age_days} days ago")
    if age_days < 180:
        return Finding("domain_age", True, 15, f"Domain is fairly new ({age_days} days old)")
    return Finding("domain_age", False, 0, f"Domain is well established ({age_days} days old)")


# ---------- Google Safe Browsing ----------

def check_safe_browsing(url: str, post=requests.post) -> Finding:
    """Ask Google whether this URL is on its phishing / malware blacklists."""
    api_key = os.getenv("SAFE_BROWSING_API_KEY", "")
    if not api_key or api_key == "your_key_here":
        return Finding("safe_browsing", False, 0, "Safe Browsing check skipped (no API key configured)")

    target = url.strip()
    if "://" not in target:
        target = "http://" + target

    body = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": list(_THREAT_NAMES),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": target}],
        },
    }

    try:
        response = post(SAFE_BROWSING_ENDPOINT, params={"key": api_key}, json=body, timeout=5)
        if response.status_code != 200:
            return Finding("safe_browsing", False, 0,
                           f"Safe Browsing check failed (HTTP {response.status_code})")
        matches = response.json().get("matches", [])
    except (requests.RequestException, ValueError):
        return Finding("safe_browsing", False, 0, "Safe Browsing check failed (could not get a valid answer from Google)")

    if not matches:
        return Finding("safe_browsing", False, 0, "URL is not on Google's Safe Browsing blacklists")

    threats = sorted({_THREAT_NAMES.get(m.get("threatType"), "a known threat") for m in matches})
    return Finding("safe_browsing", True, 100,
                   "Google Safe Browsing lists this URL for: " + ", ".join(threats))


def analyze_url(url: str, include_network: bool = True) -> list[Finding]:
    parsed = _parse(url)
    findings = [
        check_https(parsed),
        check_ip_address(parsed),
        check_length(url),
        check_subdomains(parsed),
        check_at_symbol(parsed),
        check_typosquatting(parsed),
    ]
    if include_network:
        findings.append(check_domain_age(parsed))
        findings.append(check_safe_browsing(url))
    return findings
