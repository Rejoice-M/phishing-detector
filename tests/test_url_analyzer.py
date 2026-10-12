from app.analyzers.url_analyzer import (
    _parse,
    analyze_url,
    check_at_symbol,
    check_https,
    check_ip_address,
    check_length,
    check_subdomains,
)
from app.scoring import calculate_score, risk_level


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
    score = calculate_score(analyze_url("https://example.com"))
    assert score == 0
    assert risk_level(score) == "low"


def test_obviously_bad_url_scores_high():
    score = calculate_score(analyze_url("http://192.168.1.1/login@secure"))
    assert risk_level(score) == "high"
