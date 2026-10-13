# test_scoring_samples.py
# Purpose: a table of sample URLs and the risk level each one should get, using only the
# offline checks. Run pytest after changing any point values in url_analyzer.py to see
# which URLs changed level. (WHOIS and Safe Browsing add points on top of these in real use.)

import pytest

from app.analyzers.url_analyzer import analyze_url
from app.scoring import calculate_score, risk_level

SAMPLES = [
    # Legitimate or harmless
    ("https://www.example.com", "low"),
    ("https://www.fnb.co.za/login", "low"),
    ("http://example.com", "low"),
    # Lookalikes of a brand on their own are already high
    ("https://paypa1.com", "high"),
    ("https://paypal.xyz", "high"),
    # One suspicious signal is medium
    ("http://paypa1-secure-login.com/verify", "medium"),
    ("https://paypal.example.com/login", "medium"),
    ("http://fnb-secure-login.co.za", "medium"),
    ("http://192.168.1.1/login", "medium"),
    ("https://google.com@evil.com/login", "medium"),
    # Several signals stacking up is high
    ("http://user@192.168.1.1/login", "high"),
    ("https://login.secure.account.paypal.example.com/verify", "high"),
]


@pytest.mark.parametrize("url, expected", SAMPLES)
def test_sample_url_risk_level(url, expected):
    score = calculate_score(analyze_url(url, include_network=False))
    assert risk_level(score) == expected, f"{url} scored {score}"
