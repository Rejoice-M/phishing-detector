# main.py
# Purpose: the API entry point (FastAPI). This is the file uvicorn starts.
#   - GET /            : health check, returns {"status": "ok"}
#   - POST /analyze/url: takes {"url": "..."}, runs the URL checks, and returns the score,
#                        risk level and every finding with its reason
# Interactive docs for trying it out: http://127.0.0.1:8000/docs
# Run with: uvicorn app.main:app --reload

"""
The endpoint (main.py) exposes all of this as POST /analyze/url.
You send {"url": "..."} and get back the score, the risk level, and every finding.
"""
from dataclasses import asdict

from fastapi import FastAPI
from pydantic import BaseModel

from app.analyzers.url_analyzer import analyze_url
from app.scoring import calculate_score, risk_level

app = FastAPI(title="Phishing Detector")


class UrlRequest(BaseModel):
    url: str


@app.get("/")
def health():
    return {"status": "ok"}


@app.post("/analyze/url")
def analyze(request: UrlRequest):
    findings = analyze_url(request.url)
    score = calculate_score(findings)
    return {
        "url": request.url,
        "score": score,
        "risk_level": risk_level(score),
        "findings": [asdict(f) for f in findings],
    }
