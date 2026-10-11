from fastapi import FastAPI

app = FastAPI(title="Phishing Detector")


@app.get("/")
def health():
    return {"status": "ok"}
