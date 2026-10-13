# test_safe_browsing.py
# Purpose: tests for the Google Safe Browsing check using a fake "Google" response,
# so no real API calls (and no real API key) are needed.

import requests

from app.analyzers.url_analyzer import check_safe_browsing


class FakeResponse:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self._data = data if data is not None else {}

    def json(self):
        return self._data


def _should_not_be_called(*args, **kwargs):
    raise AssertionError("Google should not be contacted without an API key")


def test_missing_key_skips_check(monkeypatch):
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
    finding = check_safe_browsing("http://example.com", post=_should_not_be_called)
    assert not finding.triggered
    assert "skipped" in finding.reason


def test_placeholder_key_skips_check(monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "your_key_here")
    finding = check_safe_browsing("http://example.com", post=_should_not_be_called)
    assert not finding.triggered
    assert "skipped" in finding.reason


def test_match_is_flagged(monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "test-key")
    fake = lambda *args, **kwargs: FakeResponse(200, {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})
    finding = check_safe_browsing("http://bad.example", post=fake)
    assert finding.triggered
    assert finding.points == 100
    assert "phishing" in finding.reason


def test_no_match_is_clean(monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "test-key")
    fake = lambda *args, **kwargs: FakeResponse(200, {})
    assert not check_safe_browsing("https://example.com", post=fake).triggered


def test_api_error_is_not_penalised(monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "test-key")
    fake = lambda *args, **kwargs: FakeResponse(403)
    finding = check_safe_browsing("https://example.com", post=fake)
    assert not finding.triggered
    assert "failed" in finding.reason


def test_network_error_is_not_penalised(monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "test-key")

    def broken(*args, **kwargs):
        raise requests.ConnectionError("no internet")

    finding = check_safe_browsing("https://example.com", post=broken)
    assert not finding.triggered
    assert "failed" in finding.reason


def test_request_contains_key_and_url(monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "test-key")
    captured = {}

    def fake(endpoint, **kwargs):
        captured.update(kwargs)
        return FakeResponse(200, {})

    check_safe_browsing("https://example.com/page", post=fake)
    assert captured["params"]["key"] == "test-key"
    assert captured["json"]["threatInfo"]["threatEntries"][0]["url"] == "https://example.com/page"


def test_missing_scheme_is_added_before_sending(monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "test-key")
    captured = {}

    def fake(endpoint, **kwargs):
        captured.update(kwargs)
        return FakeResponse(200, {})

    check_safe_browsing("example.com", post=fake)
    assert captured["json"]["threatInfo"]["threatEntries"][0]["url"] == "http://example.com"
