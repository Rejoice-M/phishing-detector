# main.py
# Purpose: the API entry point (FastAPI). This is the file uvicorn starts.
#   - GET /              : health check, returns {"status": "ok"}
#   - POST /analyze/url  : takes {"url": "..."}, runs the URL checks, and returns the score,
#                          risk level and every finding with its reason
#   - POST /analyze/email: takes an uploaded .eml file, runs the header and body checks, and
#                          returns the same kind of result
# Interactive docs for trying it out: http://127.0.0.1:8000/docs
# Run with: uvicorn app.main:app --reload

from dataclasses import asdict

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

from app.analyzers.email_analyzer import analyze_email
from app.analyzers.url_analyzer import analyze_url
from app.scoring import calculate_score, risk_level

app = FastAPI(title="Phishing Detector")

MAX_EMAIL_BYTES = 5 * 1024 * 1024  # refuse uploads over 5 MB


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


@app.post("/analyze/email")
async def analyze_email_upload(file: UploadFile = File(...)):
    raw = await file.read(MAX_EMAIL_BYTES + 1)
    if not raw:
        raise HTTPException(status_code=400, detail="The uploaded file is empty")
    if len(raw) > MAX_EMAIL_BYTES:
        raise HTTPException(status_code=413, detail="Email file is too large (5 MB limit)")

    # The link checks can wait on WHOIS / Google, so run them off the main server loop
    findings = await run_in_threadpool(analyze_email, raw)
    score = calculate_score(findings)
    return {
        "filename": file.filename,
        "score": score,
        "risk_level": risk_level(score),
        "findings": [asdict(f) for f in findings],
    }
