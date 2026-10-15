# test_api.py
# Purpose: tests for the web routes using FastAPI's test client (no server needed):
# the dashboard and its files are served, /health works, and the email upload endpoint
# rejects empty files and analyzes a sample email. No internet is used (legit.eml has no links).

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
SAMPLES = Path(__file__).parent.parent / "samples"


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_dashboard_page_is_served():
    response = client.get("/")
    assert response.status_code == 200
    assert "Phishing Detector" in response.text


def test_static_files_are_served():
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/style.css").status_code == 200


def test_empty_email_upload_is_rejected():
    response = client.post("/analyze/email", files={"file": ("empty.eml", b"")})
    assert response.status_code == 400


def test_email_upload_returns_a_result():
    raw = (SAMPLES / "legit.eml").read_bytes()
    response = client.post("/analyze/email", files={"file": ("legit.eml", raw)})
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "legit.eml"
    assert data["score"] == 0
    assert data["risk_level"] == "low"
