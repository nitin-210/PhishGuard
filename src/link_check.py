"""
link_check.py
-------------
Looks up the REAL-WORLD reputation of a URL using two free security services:

  * VirusTotal  -> aggregates 90+ antivirus/URL scanners
  * urlscan.io  -> scans the page in a sandbox and records what it does

Your AI model in Phase 1 judges an email from its text. This module adds a
second, independent opinion based on live threat intelligence about the links.

NO API KEY?  No problem. Each function checks for its key and, if missing,
returns a "skipped" result instead of crashing. So the backend still runs and
falls back to the model-only score.

Set keys as environment variables (see .env.example):
    VIRUSTOTAL_API_KEY=...
    URLSCAN_API_KEY=...
"""

import os
import base64
import requests

VT_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
URLSCAN_KEY = os.environ.get("URLSCAN_API_KEY", "").strip()

TIMEOUT = 15  # seconds; never let a slow lookup hang the whole request


def _result(url, source, verdict, malicious=0, detail="", link=""):
    """Uniform result shape so the API can treat every source the same way."""
    return {"url": url, "source": source, "verdict": verdict,
            "malicious": malicious, "detail": detail, "link": link}


# ---------------------------------------------------------------------------
# VirusTotal (API v3)
# ---------------------------------------------------------------------------
def check_virustotal(url):
    if not VT_KEY:
        return _result(url, "virustotal", "skipped", detail="no API key set")
    try:
        # VirusTotal identifies a URL by the base64 (no padding) of the URL text.
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VT_KEY}, timeout=TIMEOUT)
        if r.status_code == 404:
            # Not seen before -> submit it for scanning (result will be ready later)
            requests.post("https://www.virustotal.com/api/v3/urls",
                          headers={"x-apikey": VT_KEY},
                          data={"url": url}, timeout=TIMEOUT)
            return _result(url, "virustotal", "unknown",
                           detail="not seen before; submitted for scanning")
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        mal = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        verdict = "malicious" if mal > 0 else "clean"
        return _result(url, "virustotal", verdict, malicious=mal,
                       detail=f"{mal} engines flagged this URL",
                       link=f"https://www.virustotal.com/gui/url/{url_id}")
    except Exception as e:
        return _result(url, "virustotal", "error", detail=str(e)[:120])


# ---------------------------------------------------------------------------
# urlscan.io (API v1)
# ---------------------------------------------------------------------------
def check_urlscan(url):
    if not URLSCAN_KEY:
        return _result(url, "urlscan", "skipped", detail="no API key set")
    try:
        # First, look for an EXISTING scan of this URL (fast, no new scan needed).
        s = requests.get("https://urlscan.io/api/v1/search/",
                         params={"q": f'page.url:"{url}"', "size": 1},
                         headers={"API-Key": URLSCAN_KEY}, timeout=TIMEOUT)
        s.raise_for_status()
        results = s.json().get("results", [])
        if results:
            res = results[0]
            mal = 1 if res.get("verdicts", {}).get("overall", {}).get("malicious") else 0
            verdict = "malicious" if mal else "clean"
            return _result(url, "urlscan", verdict, malicious=mal,
                           detail="found a prior sandbox scan",
                           link=res.get("result", ""))
        # No prior scan -> submit a new one (it runs asynchronously).
        # "unlisted" works on free accounts; "private" needs a paid plan.
        sub = requests.post("https://urlscan.io/api/v1/scan/",
                            headers={"API-Key": URLSCAN_KEY},
                            json={"url": url, "visibility": "unlisted"},
                            timeout=TIMEOUT)
        sub.raise_for_status()
        return _result(url, "urlscan", "unknown",
                       detail="submitted a new sandbox scan (ready in ~30s)",
                       link=sub.json().get("result", ""))
    except Exception as e:
        return _result(url, "urlscan", "error", detail=str(e)[:120])


def analyze_links(urls):
    """Run both services on every URL. Returns a flat list of result dicts."""
    out = []
    for url in urls:
        out.append(check_virustotal(url))
        out.append(check_urlscan(url))
    return out


def links_are_malicious(link_results):
    """True if ANY service flagged ANY link as malicious."""
    return any(r["verdict"] == "malicious" for r in link_results)
