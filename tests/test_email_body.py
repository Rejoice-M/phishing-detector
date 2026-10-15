# test_email_body.py
# Purpose: tests for the email body checks: urgency wording, misleading links, link scanning,
# and the code that pulls text and links out of plain-text and HTML emails.
# Nothing here touches the internet (link checks run with include_network=False).

from pathlib import Path

from app.analyzers.email_analyzer import (
    analyze_email,
    check_link_mismatch,
    check_links,
    check_urgency,
    extract_content,
    parse_email,
)
from app.scoring import calculate_score, risk_level

SAMPLES = Path(__file__).parent.parent / "samples"


def make_email(body, content_type="text/plain", subject="Hello"):
    headers = (
        "From: a@example.com\r\n"
        f"Subject: {subject}\r\n"
        f"Content-Type: {content_type}; charset=utf-8\r\n"
    )
    return parse_email(headers + "\r\n" + body)


# ---------- Urgency ----------

def test_single_urgency_phrase_scores_low():
    finding = check_urgency("Please act now")
    assert finding.triggered and finding.points == 10


def test_several_urgency_phrases_score_higher():
    finding = check_urgency("Urgent: your account will be suspended immediately")
    assert finding.triggered and finding.points == 20


def test_calm_email_is_clean():
    assert not check_urgency("Your statement is ready. Log in to view it.").triggered


def test_urgency_is_case_insensitive():
    assert check_urgency("ACT NOW").triggered


def test_phrase_inside_another_word_is_ignored():
    assert not check_urgency("This is a nonurgent reminder.").triggered


# ---------- Link text vs real destination ----------

def test_misleading_link_text_flagged():
    finding = check_link_mismatch([("http://evil-site.com/login", "www.paypal.com")])
    assert finding.triggered and finding.points == 40


def test_matching_link_text_is_clean():
    assert not check_link_mismatch([("https://www.paypal.com/login", "paypal.com")]).triggered


def test_plain_label_is_clean():
    assert not check_link_mismatch([("http://evil-site.com", "Click here")]).triggered


def test_file_name_in_link_text_is_ignored():
    assert not check_link_mismatch([("https://example.com/download", "invoice.pdf")]).triggered


def test_non_http_links_are_ignored():
    assert not check_link_mismatch([("mailto:a@example.com", "example.com")]).triggered


def test_subdomain_difference_is_not_a_mismatch():
    assert not check_link_mismatch([("https://mail.example.com/x", "www.example.com")]).triggered


# ---------- Link scanning ----------

def test_no_links_is_clean():
    finding = check_links([], include_network=False)
    assert not finding.triggered
    assert "No links" in finding.reason


def test_suspicious_link_is_flagged():
    finding = check_links(["http://paypa1-secure-login.com/verify"], include_network=False)
    assert finding.triggered and finding.points == 45


def test_harmless_link_is_clean():
    assert not check_links(["https://www.example.com"], include_network=False).triggered


def test_worst_link_is_reported():
    links = ["https://www.example.com", "http://user@192.168.1.1/login"]
    finding = check_links(links, include_network=False)
    assert finding.points == 70
    assert "192.168.1.1" in finding.reason


def test_only_the_first_links_are_checked():
    links = [f"https://www.example.com/{i}" for i in range(12)]
    finding = check_links(links, include_network=False)
    assert not finding.triggered
    assert "first 8 of 12" in finding.reason


# ---------- Reading the email body ----------

def test_html_email_text_and_links_extracted():
    body = '<p>Welcome aboard</p><a href="http://evil-site.com/x">www.paypal.com</a>'
    content = extract_content(make_email(body, "text/html"))
    assert content.anchors == [("http://evil-site.com/x", "www.paypal.com")]
    assert content.links == ["http://evil-site.com/x"]
    assert "Welcome aboard" in content.text


def test_plain_text_urls_found_without_trailing_punctuation():
    content = extract_content(make_email("Visit http://example.com/a, then https://example.org/b."))
    assert content.links == ["http://example.com/a", "https://example.org/b"]


def test_script_and_style_text_is_ignored():
    body = "<style>p {color: red}</style><script>var x = 'act now';</script><p>Hi there</p>"
    content = extract_content(make_email(body, "text/html"))
    assert "act now" not in content.text.lower()
    assert "Hi there" in content.text


def test_duplicate_links_are_removed():
    content = extract_content(make_email("http://a.com http://a.com"))
    assert content.links == ["http://a.com"]


# ---------- Sample files ----------

def results_for(name):
    findings = analyze_email((SAMPLES / name).read_bytes(), include_network=False)
    return {f.check: f for f in findings}, calculate_score(findings)


def test_legit_sample_has_clean_body():
    results, _ = results_for("legit.eml")
    assert not results["urgency"].triggered
    assert not results["link_mismatch"].triggered
    assert "No links" in results["links"].reason


def test_phishing_sample_has_suspicious_body():
    results, _ = results_for("phishing.eml")
    assert results["urgency"].triggered
    assert results["links"].triggered


def test_html_sample_flags_misleading_link():
    results, score = results_for("phishing_html.eml")
    assert results["link_mismatch"].triggered
    assert results["links"].triggered
    assert results["urgency"].triggered
    assert risk_level(score) == "high"
