# test_email_analyzer.py
# Purpose: tests for the email header checks. Emails are built from short strings,
# so nothing touches the internet. The last two tests run the sample .eml files in samples/.

from pathlib import Path

from app.analyzers.email_analyzer import (
    analyze_email,
    check_authentication,
    check_display_name,
    check_reply_to,
    check_sender_domain,
    parse_email,
)
from app.scoring import calculate_score, risk_level

SAMPLES = Path(__file__).parent.parent / "samples"


def make_email(headers, body="Hello"):
    lines = [f"{name}: {value}" for name, value in headers.items()]
    return parse_email("\r\n".join(lines) + "\r\n\r\n" + body)


def auth(headers):
    return {f.check: f for f in check_authentication(make_email(headers))}


def with_auth(results):
    return {"From": "a@example.com", "Authentication-Results": results}


# ---------- SPF / DKIM / DMARC ----------

def test_spf_fail_flagged():
    finding = auth(with_auth("mx.test; spf=fail; dkim=pass; dmarc=pass"))["spf"]
    assert finding.triggered and finding.points == 20


def test_dkim_fail_flagged():
    finding = auth(with_auth("mx.test; spf=pass; dkim=fail; dmarc=pass"))["dkim"]
    assert finding.triggered and finding.points == 20


def test_dmarc_fail_flagged():
    finding = auth(with_auth("mx.test; spf=pass; dkim=pass; dmarc=fail"))["dmarc"]
    assert finding.triggered and finding.points == 30


def test_all_pass_is_clean():
    results = auth(with_auth("mx.test; spf=pass; dkim=pass; dmarc=pass"))
    assert not any(f.triggered for f in results.values())


def test_softfail_counts_as_failure():
    assert auth(with_auth("mx.test; spf=softfail; dkim=pass; dmarc=pass"))["spf"].triggered


def test_missing_header_is_not_penalised():
    results = auth({"From": "a@example.com"})
    assert not any(f.triggered for f in results.values())
    assert "not found" in results["spf"].reason


def test_received_spf_is_used_as_fallback():
    results = auth({"From": "a@example.com", "Received-SPF": "fail (example.com: not allowed)"})
    assert results["spf"].triggered


def test_none_result_is_not_penalised():
    results = auth(with_auth("mx.test; spf=none; dkim=none; dmarc=none"))
    assert not any(f.triggered for f in results.values())


# ---------- Reply-To ----------

def test_reply_to_different_domain_flagged():
    msg = make_email({"From": "support@example.com", "Reply-To": "help@other.net"})
    finding = check_reply_to(msg)
    assert finding.triggered and finding.points == 20


def test_reply_to_same_domain_is_clean():
    msg = make_email({"From": "support@example.com", "Reply-To": "help@example.com"})
    assert not check_reply_to(msg).triggered


def test_reply_to_subdomain_of_same_domain_is_clean():
    msg = make_email({"From": "a@example.com", "Reply-To": "b@mail.example.com"})
    assert not check_reply_to(msg).triggered


def test_no_reply_to_is_clean():
    assert not check_reply_to(make_email({"From": "a@example.com"})).triggered


# ---------- Display name ----------

def test_brand_name_with_unrelated_domain_flagged():
    msg = make_email({"From": '"PayPal Support" <security@evil-site.com>'})
    finding = check_display_name(msg)
    assert finding.triggered and finding.points == 35


def test_brand_name_with_real_domain_is_clean():
    assert not check_display_name(make_email({"From": '"FNB" <noreply@fnb.co.za>'})).triggered


def test_multi_word_brand_name_flagged():
    assert check_display_name(make_email({"From": '"Standard Bank" <alerts@evil-site.com>'})).triggered


def test_plain_name_is_clean():
    assert not check_display_name(make_email({"From": '"John Smith" <john@example.com>'})).triggered


def test_brand_inside_another_word_is_clean():
    assert not check_display_name(make_email({"From": '"Pineapple Co" <hello@example.com>'})).triggered


# ---------- Sender domain ----------

def test_lookalike_sender_domain_flagged():
    finding = check_sender_domain(make_email({"From": "a@paypa1.com"}))
    assert finding.triggered and finding.check == "sender_domain"


def test_legit_sender_domain_is_clean():
    assert not check_sender_domain(make_email({"From": "a@fnb.co.za"})).triggered


# ---------- Sample files ----------

def test_legit_sample_scores_low():
    score = calculate_score(analyze_email((SAMPLES / "legit.eml").read_bytes()))
    assert score == 0
    assert risk_level(score) == "low"


def test_phishing_sample_scores_high():
    score = calculate_score(analyze_email((SAMPLES / "phishing.eml").read_bytes()))
    assert risk_level(score) == "high"
