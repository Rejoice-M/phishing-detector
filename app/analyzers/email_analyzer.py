# email_analyzer.py
# Purpose: takes a raw email (.eml) and runs phishing checks on its headers and body.
# Each check returns a Finding (the same type used by url_analyzer.py).
#
# Header checks:
#   1. SPF / DKIM / DMARC - reads the Authentication-Results header that the RECEIVING mail
#                           server added, and flags failures. A missing header is not penalised
#                           because the result simply can't be verified.
#   2. Reply-To mismatch  - flags replies going to a different domain than the sender's
#   3. Display name       - flags "PayPal Support" <someone@unrelated-domain.com>
#   4. Sender domain      - reuses the typosquatting check on the sender's domain (paypa1.com)
#
# Body checks:
#   5. Urgency wording    - flags pressure phrases ("act now", "will be suspended") in the
#                           subject and body
#   6. Link mismatch      - flags links whose visible text shows one domain but whose real
#                           destination is another
#   7. Links              - runs the URL checks from url_analyzer.py on every link in the email
#                           and reports the worst one
#
# analyze_email() runs all checks and returns the list of findings.
# Pass include_network=False to skip WHOIS / Safe Browsing lookups on the links (tests do this).

import re
from dataclasses import dataclass, field, replace
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

import tldextract

from app.analyzers.url_analyzer import LEGIT_DOMAINS, Finding, analyze_url, check_typosquatting
from app.scoring import calculate_score, risk_level

_extract = tldextract.TLDExtract(suffix_list_urls=())
_BRANDS = sorted({d.split(".")[0] for d in LEGIT_DOMAINS})

_AUTH_FAIL = {"fail", "softfail", "permerror"}
_AUTH_POINTS = {"spf": 20, "dkim": 20, "dmarc": 30}

MAX_LINKS = 8  # only the first few links are checked, since each can need network lookups

URGENCY_PHRASES = [
    "act now", "urgent", "urgently", "immediately", "within 24 hours", "within 48 hours",
    "will be suspended", "has been suspended", "will be closed", "will be locked",
    "verify your account", "verify your details", "verify your identity",
    "confirm your identity", "confirm your account", "unusual activity",
    "suspicious activity", "final notice", "last warning", "dear customer",
    "update your payment",
]

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_TEXT_DOMAIN_RE = re.compile(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", re.IGNORECASE)


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


def _parse_url(url: str):
    try:
        return urlparse(url)
    except ValueError:  # e.g. a broken IPv6-style address like http://[abc
        return None


def _short(url: str, limit: int = 80) -> str:
    return url if len(url) <= limit else url[:limit] + "..."


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


# ---------- Reading the email body ----------

class _HtmlScanner(HTMLParser):
    """Collects the visible text of an HTML email and every <a> link with its visible text."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text_parts = []
        self.links = []  # (href, visible text)
        self._href = None
        self._anchor_text = []
        self._skip = 0  # >0 while inside <script> or <style>

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._href = dict(attrs).get("href")
            self._anchor_text = []

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href is not None:
            visible = " ".join("".join(self._anchor_text).split())
            self.links.append((self._href.strip(), visible))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._anchor_text.append(data)


@dataclass
class EmailContent:
    text: str                                   # subject + readable body text
    anchors: list = field(default_factory=list)  # (href, visible text) pairs from HTML links
    links: list = field(default_factory=list)    # every unique http(s) URL found


def _body_parts(msg: EmailMessage):
    """Return (plain text, html) from the email, ignoring attachments."""
    plain, html = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type not in ("text/plain", "text/html"):
            continue
        try:
            text = part.get_content()
        except Exception:  # unknown character set and similar problems
            payload = part.get_payload(decode=True) or b""
            text = payload.decode("utf-8", errors="replace")
        (plain if content_type == "text/plain" else html).append(text)
    return "\n".join(plain), "\n".join(html)


def extract_content(msg: EmailMessage) -> EmailContent:
    plain, html = _body_parts(msg)

    scanner = _HtmlScanner()
    if html:
        try:
            scanner.feed(html)
            scanner.close()
        except Exception:
            pass  # badly broken HTML: use whatever was collected so far

    body_text = " ".join(part for part in (plain, " ".join(scanner.text_parts)) if part)
    text = f"{msg.get('Subject', '') or ''} {body_text}"

    candidates = [href for href, _ in scanner.links] + _URL_RE.findall(body_text)
    links = []
    for candidate in candidates:
        url = candidate.strip().rstrip(".,;:!?)]}>'\"")
        parsed = _parse_url(url)
        if parsed and parsed.scheme.lower() in ("http", "https") and url not in links:
            links.append(url)
    return EmailContent(text=text, anchors=scanner.links, links=links)


# ---------- Body checks ----------

def check_urgency(text: str) -> Finding:
    lowered = text.lower()
    found = [p for p in URGENCY_PHRASES if re.search(r"\b" + re.escape(p) + r"\b", lowered)]
    if not found:
        return Finding("urgency", False, 0, "No pressure or urgency wording found")
    points = 10 if len(found) == 1 else 20
    shown = ", ".join(f"'{p}'" for p in found[:5])
    return Finding("urgency", True, points, f"Contains pressure wording ({len(found)} phrase(s)): {shown}")


def _text_registered_domain(text: str) -> str:
    """If a link's visible text looks like a web address, return its registered domain."""
    match = _TEXT_DOMAIN_RE.search(text or "")
    if not match:
        return ""
    return _extract(match.group(1).lower()).top_domain_under_public_suffix  # "" if not a real domain


def _link_domain(href: str) -> str:
    parsed = _parse_url(href)
    host = parsed.hostname if parsed else ""
    if not host:
        return ""
    return _extract(host).top_domain_under_public_suffix or host


def check_link_mismatch(anchors) -> Finding:
    mismatches = []
    for href, text in anchors:
        parsed = _parse_url(href)
        if not parsed or parsed.scheme.lower() not in ("http", "https"):
            continue
        shown = _text_registered_domain(text)
        actual = _link_domain(href)
        if shown and actual and shown != actual:
            mismatches.append((shown, actual))

    if not mismatches:
        return Finding("link_mismatch", False, 0, "No links with misleading text")
    shown, actual = mismatches[0]
    extra = f" (+{len(mismatches) - 1} more)" if len(mismatches) > 1 else ""
    return Finding("link_mismatch", True, 40,
                   f"A link displays '{shown}' but actually goes to '{actual}'{extra}")


def check_links(links, include_network: bool = True) -> Finding:
    if not links:
        return Finding("links", False, 0, "No links found in the email")

    checked = links[:MAX_LINKS]
    if len(links) > MAX_LINKS:
        scope = f"the first {MAX_LINKS} of {len(links)} links"
    else:
        scope = f"{len(links)} link(s)"

    worst_url, worst_score, worst_findings = None, -1, []
    for link in checked:
        try:
            findings = analyze_url(link, include_network=include_network)
        except ValueError:
            continue  # a link too malformed to parse
        score = calculate_score(findings)
        if score > worst_score:
            worst_url, worst_score, worst_findings = link, score, findings

    if worst_url is None or risk_level(worst_score) == "low":
        return Finding("links", False, 0, f"Checked {scope}; none looked suspicious")

    reasons = "; ".join(f.reason for f in worst_findings if f.triggered)
    return Finding("links", True, worst_score,
                   f"Worst link {_short(worst_url)} scored {worst_score}/100 "
                   f"({risk_level(worst_score)}): {reasons}. Checked {scope}.")


def analyze_email(raw, include_network: bool = True) -> list[Finding]:
    msg = parse_email(raw)
    content = extract_content(msg)

    findings = []
    findings.extend(check_authentication(msg))
    findings.append(check_reply_to(msg))
    findings.append(check_display_name(msg))
    findings.append(check_sender_domain(msg))
    findings.append(check_urgency(content.text))
    findings.append(check_link_mismatch(content.anchors))
    findings.append(check_links(content.links, include_network))
    return findings
