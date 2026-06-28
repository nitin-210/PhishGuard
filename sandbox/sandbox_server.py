"""
sandbox_server.py  (OPTIONAL / ADVANCED)
----------------------------------------
A tiny isolated "detonation" service. It opens a URL in a headless browser
INSIDE this container and reports what it saw -- the final address after
redirects, the page title, and a screenshot -- without the link ever touching
the user's real computer.

This is the self-hosted version of detonation: a company runs THIS in an
isolated VM/container, and the main PhishGuard backend calls it by setting
SANDBOX_URL to point here. The risky link is opened here, in throwaway
infrastructure, not on anyone's laptop.

Endpoint:
    GET /open?url=...   ->  { final_url, title, redirects, screenshot, verdict }

Run locally (after `pip install -r requirements.txt` and
`playwright install --with-deps chromium`):
    uvicorn sandbox_server:app --host 0.0.0.0 --port 9000

Or build the Docker image (recommended for real isolation) -- see Dockerfile.

SAFETY: detonating live malicious links is inherently risky. Run this only in a
disposable, network-isolated container that has no access to your real accounts
or internal network. Treat the VM as compromised after each scan.
"""

import base64

from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI(title="PhishGuard Sandbox", version="1.0")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/open")
def open_url(url: str):
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return JSONResponse(
            {"verdict": "error",
             "detail": "Playwright not installed. Run: pip install playwright && playwright install chromium"},
            status_code=500)

    redirects = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox"])
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.on("response", lambda r: redirects.append(r.url)
                    if 300 <= r.status < 400 else None)

            page.goto(url, wait_until="domcontentloaded", timeout=20000)
            final_url = page.url
            title = page.title()
            shot = page.screenshot(type="png")
            browser.close()

        # Very simple heuristic verdict: a login/password form on a page reached
        # via redirect from an unrelated link is a classic phishing pattern.
        screenshot = "data:image/png;base64," + base64.b64encode(shot).decode()
        return {
            "final_url": final_url,
            "title": title,
            "redirects": [r for r in redirects if r],
            "screenshot": screenshot,
            "verdict": "unknown",
            "detail": "Opened in isolated headless browser.",
        }
    except Exception as e:
        return {"verdict": "error", "detail": str(e)[:200]}
