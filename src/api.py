"""
api.py
------
The PhishGuard backend. It exposes a web API that the future Gmail/Outlook
extension will call. It combines TWO opinions into one verdict:

    1. The AI model (Phase 1)  -> judges the email text
    2. Live link reputation    -> VirusTotal + urlscan.io judge the links

Endpoints:
    GET  /health    -> quick check that the server is alive
    POST /analyze   -> send an email, get back a verdict + reasons

Run the server:
    uvicorn src.api:app --reload
Then open the interactive docs at:  http://127.0.0.1:8000/docs
"""

import os
import re
import sys

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import URL_RE
from predict import load_model, score_email
from link_check import analyze_links, links_are_malicious
from detonate import detonate_url

app = FastAPI(title="PhishGuard API", version="2.0")

# Allow the browser extension (and any local page) to call this API.
# For a local dev tool this is fine; tighten allow_origins for production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pull "From:" / "Subject:" lines out of a raw pasted email.
_FROM_RE = re.compile(r"^\s*from:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_SUBJ_RE = re.compile(r"^\s*subject:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


def _looks_like_url_or_domain(s):
    s = s.strip()
    return bool(re.match(r"^(https?://)?[\w.-]+\.[a-z]{2,}(/\S*)?$", s, re.IGNORECASE)) and " " not in s

# The friendly web page lives in ../web/index.html
WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")


@app.get("/")
def home():
    """Serve the user-facing web UI (no JSON/code for the user to read)."""
    return FileResponse(os.path.join(WEB_DIR, "index.html"))

# Load the trained model ONCE when the server starts (not on every request).
try:
    MODEL_BUNDLE = load_model()
except FileNotFoundError:
    MODEL_BUNDLE = None  # server still starts; /analyze will warn to train first


# ---- Request / response shapes (FastAPI validates these automatically) ----
class EmailIn(BaseModel):
    sender: str = Field("", examples=["PayPal <security@paypa1-security.com>"])
    subject: str = Field("", examples=["Your account has been limited"])
    body: str = Field("", examples=["Verify now: http://192.168.0.5/login"])
    # Free-form box: paste a link, a domain, or an entire raw email here.
    text: str = Field("", examples=["http://paypa1-security.com/login"])


def _resolve_input(email):
    """Turn whatever the user sent into (sender, subject, body)."""
    sender, subject, body = email.sender, email.subject, email.body
    text = (email.text or "").strip()
    if text and not (sender or subject or body):
        if _looks_like_url_or_domain(text):
            # Just a link or domain -> analyse it as the body.
            body = text if text.lower().startswith("http") else "http://" + text
        else:
            # A whole pasted email -> pull headers out, keep full text as body.
            mf, ms = _FROM_RE.search(text), _SUBJ_RE.search(text)
            if mf:
                sender = mf.group(1).strip()
            if ms:
                subject = ms.group(1).strip()
            body = text
    return sender, subject, body


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": MODEL_BUNDLE is not None}


class LinkIn(BaseModel):
    url: str = Field(..., examples=["http://paypa1-security.com/login"])


@app.post("/detonate")
def detonate(link: LinkIn):
    """Safely analyse a single link: offline structure check + (if configured)
    a live sandbox detonation that opens the link in isolation."""
    return detonate_url(link.url)


@app.post("/analyze")
def analyze(email: EmailIn):
    if MODEL_BUNDLE is None:
        return {"error": "Model not trained. Run 'python src/train.py' first."}

    sender, subject, body = _resolve_input(email)
    email_dict = {"sender": sender, "subject": subject, "body": body}

    # 1) AI model opinion (text-based)
    model_result = score_email(email_dict, MODEL_BUNDLE)

    # 2) Live link reputation (network-based). Skips gracefully without API keys.
    urls = URL_RE.findall(f"{subject}\n{body}")
    link_results = analyze_links(urls)
    bad_link = links_are_malicious(link_results)

    # 3) Combine into a single verdict. Three layers, strongest wins:
    #      model score  ->  rule safety net (inside score_email)  ->  live link intel
    #    A confirmed-malicious link overrides everything -> definitely phishing.
    combined_score = model_result["score"]      # already includes rule escalation
    combined_verdict = model_result["verdict"]
    reasons = list(model_result["reasons"])

    if bad_link:
        combined_verdict = "PHISHING"
        combined_score = max(combined_score, 0.95)
        reasons.insert(0, "a link was flagged as malicious by threat-intelligence services")

    return {
        "final_verdict": combined_verdict,
        "final_score": round(combined_score, 3),
        "model_prob": round(model_result["model_prob"], 3),   # raw AI model opinion
        "rule_hits": model_result["rule_hits"],                # hard rules that fired
        "reasons": reasons,
        "links_found": urls,
        "link_reputation": link_results,
    }
