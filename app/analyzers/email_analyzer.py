# email_analyzer.py
# Purpose: takes a raw email (.eml) and runs phishing checks on its headers.
# Each check returns a Finding (the same type used by url_analyzer.py).
#
# Header checks (this file, part A):
#   1. SPF / DKIM / DMARC - reads the Authentication-Results header that the RECEIVING mail
#                           server added, and flags failures. A missing header is not penalised
#                           because the result simply can't be verified.
#   2. Reply-To mismatch  - flags replies going to a different domain than the sender's
#   3. Display name       - flags "PayPal Support" <someone@unrelated-domain.com>
#   4. Sender domain      - reuses the typosquatting check on the sender's domain (paypa1.com)
#
# Still to come (part B): urgency keywords, link text vs real destination, and running the
# URL checks on every link in the email body.
#
# analyze_email() runs all checks and returns the list of findings.

import re
from dataclasses import replace
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse

import tldextract

from app.analyzers.url_analyzer import LEGIT_DOMAINS, Finding, check_typosquatting

_extract = tldextract.TLDExtract(suffix_list_urls=())
_BRANDS = sorted({d.split(".")[0] for d in LEGIT_DOMAINS})

_AUTH_FAIL = {"fail", "softfail", "permerror"}
_AUTH_POINTS = {"spf": 20, "dkim": 20, "dmarc": 30}


def parse_email(raw) -> EmailMessage:
    """Turn raw email text or bytes into an EmailMessage we can read headers from."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    return BytesParser(policy=policy.default).parsebytes(raw)


def _addr(msg: EmailMessage, header: str):
    """Return (display name, lowercase address) from an address header."""
    name, address = parseaddr(str(msg.get(header, "") or ""))
    return name, address.lower()


def _registered_domain(address: str) -> str:
    if "@" not in address:
        return ""
    host = address.rsplit("@", 1)[1]
    return _extract(host).top_domain_under_public_suffix


# ---------- SPF / DKIM / DMARC ----------

def _auth_results(msg: EmailMessage) -> dict:
    results = {}
    for header in msg.get_all("Authentication-Results", []):
        found = re.findall(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)", str(header), re.IGNORECASE)
        for method, result in found:
            results.setdefault(method.lower(), set()).add(result.lower())

    # Some servers only add a Received-SPF header, so use it as a fallback for SPF
    if "spf" not in results:
        received = msg.get("Received-SPF")
        if received:
            match = re.match(r"\s*([a-zA-Z]+)", str(received))
            if match:
                results["spf"] = {match.group(1).lower()}
    return results


def check_authentication(msg: EmailMessage) -> list[Finding]:
    results = _auth_results(msg)
    findings = []
    for method in ("spf", "dkim", "dmarc"):
        label = method.upper()
        found = results.get(method)
        if not found:
            findings.append(Finding(method, False, 0,
                                    f"{label} result not found in the headers, so it could not be verified"))
        elif found & _AUTH_FAIL:
            failed = ", ".join(sorted(found & _AUTH_FAIL))
            findings.append(Finding(method, True, _AUTH_POINTS[method],
                                    f"{label} check failed ({failed}), so the sender could not be verified"))
        elif "pass" in found:
            findings.append(Finding(method, False, 0, f"{label} passed"))
        else:
            findings.append(Finding(method, False, 0, f"{label} result was: {', '.join(sorted(found))}"))
    return findings


# ---------- Sender checks ----------

def check_reply_to(msg: EmailMessage) -> Finding:
    _, from_addr = _addr(msg, "From")
    _, reply_addr = _addr(msg, "Reply-To")
    if not reply_addr:
        return Finding("reply_to", False, 0, "No Reply-To header")

    from_domain = _registered_domain(from_addr)
    reply_domain = _registered_domain(reply_addr)
    if from_domain and reply_domain and from_domain != reply_domain:
        return Finding("reply_to", True, 20,
                       f"Replies go to {reply_domain}, which differs from the sender's domain ({from_domain})")
    return Finding("reply_to", False, 0, "Reply-To matches the sender's domain")


def check_display_name(msg: EmailMessage) -> Finding:
    name, address = _addr(msg, "From")
    domain = _registered_domain(address)
    if not name or not domain:
        return Finding("display_name", False, 0, "No display name to compare with the sender's domain")
    if domain in LEGIT_DOMAINS:
        return Finding("display_name", False, 0, "Sender domain is a known legitimate brand domain")

    tokens = set(re.findall(r"[a-z0-9]+", name.lower()))
    collapsed = re.sub(r"[^a-z0-9]", "", name.lower())  # "Standard Bank" -> "standardbank"
    for brand in _BRANDS:
        if brand in tokens or collapsed == brand:
            return Finding("display_name", True, 35,
                           f"Display name claims to be '{brand}' but the email comes from {domain}")
    return Finding("display_name", False, 0, "Display name does not imitate a known brand")


def check_sender_domain(msg: EmailMessage) -> Finding:
    _, address = _addr(msg, "From")
    if "@" not in address:
        return Finding("sender_domain", False, 0, "No sender address to check")
    host = address.rsplit("@", 1)[1]
    finding = check_typosquatting(urlparse("//" + host))  # same lookalike logic as for URLs
    return replace(finding, check="sender_domain")


def analyze_email(raw) -> list[Finding]:
    msg = parse_email(raw)
    findings = []
    findings.extend(check_authentication(msg))
    findings.append(check_reply_to(msg))
    findings.append(check_display_name(msg))
    findings.append(check_sender_domain(msg))
    return findings
