# test_url_analyzer.py
# Purpose: automated tests for the URL checks and the scoring. Run with: pytest
# Sections: the original checks (HTTPS, IP, length, subdomains, @), typosquatting, domain age.
# The WHOIS tests use a fake lookup function and the others pass include_network=False,
# so none of the tests touch the internet.

from datetime import datetime, timedelta, timezone

from app.analyzers.url_analyzer import (
    _parse,
    analyze_url,
    check_at_symbol,
    check_domain_age,
    check_https,
    check_ip_address,
    check_length,
    check_subdomains,
    check_typosquatting,
)
from app.scoring import calculate_score, risk_level


# ---------- Existing checks ----------

def test_http_is_flagged():
    assert check_https(_parse("http://example.com")).triggered


def test_https_is_clean():
    assert not check_https(_parse("https://example.com")).triggered


def test_missing_scheme_is_not_penalised():
    assert not check_https(_parse("example.com")).triggered


def test_ip_address_is_flagged():
    assert check_ip_address(_parse("http://192.168.1.1/login")).triggered


def test_domain_is_not_flagged_as_ip():
    assert not check_ip_address(_parse("https://example.com")).triggered


def test_long_url_is_flagged():
    assert check_length("https://example.com/" + "a" * 80).triggered


def test_short_url_is_clean():
    assert not check_length("https://example.com").triggered


def test_many_subdomains_flagged():
    assert check_subdomains(_parse("https://login.secure.account.paypal.example.com")).triggered


def test_www_is_fine():
    assert not check_subdomains(_parse("https://www.example.com")).triggered


def test_co_za_is_not_treated_as_subdomain():
    assert not check_subdomains(_parse("https://example.co.za")).triggered


def test_at_symbol_trick_flagged():
    assert check_at_symbol(_parse("https://google.com@evil.com/login")).triggered


def test_clean_url_scores_zero():
    score = calculate_score(analyze_url("https://example.com", include_network=False))
    assert score == 0
    assert risk_level(score) == "low"


def test_obviously_bad_url_scores_high():
    score = calculate_score(analyze_url("http://192.168.1.1/login@secure", include_network=False))
    assert risk_level(score) == "high"


# ---------- Typosquatting ----------

def test_digit_swap_is_flagged():
    assert check_typosquatting(_parse("https://paypa1.com")).triggered


def test_zeros_for_o_is_flagged():
    assert check_typosquatting(_parse("https://g00gle.com")).triggered


def test_rn_for_m_is_flagged():
    assert check_typosquatting(_parse("https://rnicrosoft.com")).triggered


def test_extra_letter_is_flagged():
    assert check_typosquatting(_parse("https://gooogle.com")).triggered


def test_substituted_letter_is_flagged():
    assert check_typosquatting(_parse("https://goggle.com")).triggered


def test_brand_on_unofficial_tld_is_flagged():
    assert check_typosquatting(_parse("https://paypal.xyz")).triggered


def test_brand_with_hyphenated_extras_is_flagged():
    assert check_typosquatting(_parse("https://paypal-secure-login.com")).triggered


def test_brand_in_subdomain_is_flagged():
    assert check_typosquatting(_parse("https://paypal.example.com/login")).triggered


def test_real_brand_domain_is_clean():
    assert not check_typosquatting(_parse("https://www.paypal.com")).triggered


def test_real_south_african_brand_is_clean():
    assert not check_typosquatting(_parse("https://www.fnb.co.za")).triggered


def test_unrelated_domain_is_clean():
    assert not check_typosquatting(_parse("https://example.com")).triggered


# ---------- Domain age ----------

def _created_days_ago(days):
    return lambda domain: datetime.now(timezone.utc) - timedelta(days=days)


def test_brand_new_domain_flagged_high():
    finding = check_domain_age(_parse("https://example.com"), lookup=_created_days_ago(5))
    assert finding.triggered and finding.points == 30


def test_fairly_new_domain_flagged_lower():
    finding = check_domain_age(_parse("https://example.com"), lookup=_created_days_ago(100))
    assert finding.triggered and finding.points == 15


def test_old_domain_is_clean():
    assert not check_domain_age(_parse("https://example.com"), lookup=_created_days_ago(2000)).triggered


def test_failed_lookup_is_not_penalised():
    finding = check_domain_age(_parse("https://example.com"), lookup=lambda domain: None)
    assert not finding.triggered
    assert "could not be determined" in finding.reason


def test_ip_address_skips_lookup():
    def should_not_be_called(domain):
        raise AssertionError("WHOIS should not be queried for IP addresses")

    assert not check_domain_age(_parse("http://192.168.1.1"), lookup=should_not_be_called).triggered
