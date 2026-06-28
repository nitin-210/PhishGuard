"""
detonate.py
-----------
"Detonating" a link means opening it in an ISOLATED place to see what it really
does, WITHOUT it ever touching your computer. PhishGuard does this two safe ways:

  1. safe_static_analysis(url)  -- OFFLINE. Breaks the URL apart and flags
     suspicious structure. Never makes a network request, so it is 100% safe and
     always available (no API key needed).

  2. detonate_url(url)          -- LIVE. Sends the link to a sandbox that opens
     it for us and reports back (final address after redirects, page title,
     a screenshot, and a malicious/clean verdict). Two possible sandboxes:
        * a self-hosted sandbox you/your company run  (set SANDBOX_URL), or
        * urlscan.io                                  (set URLSCAN_API_KEY).
     If neither is configured, we still return the offline static analysis.

IMPORTANT SAFETY NOTE: PhishGuard never opens the link on this machine. The live
detonation happens inside urlscan.io's sandbox or your isolated sandbox VM.
"""

import os
import re
import time
import requests

URLSCAN_KEY = os.environ.get("URLSCAN_API_KEY", "").strip()
SANDBOX_URL = os.environ.get("SANDBOX_URL", "").strip().rstrip("/")  # optional self-hosted sandbox

SUSPICIOUS_TLDS = [".top", ".xyz", ".info", ".online", ".click", ".gq", ".tk",
                   ".ml", ".work", ".zip", ".support", ".country"]
SHORTENERS = ["bit.ly", "tinyurl.com", "is.gd", "t.co", "ow.ly", "goo.gl", "rebrand.ly"]
BRANDS = ["paypal", "netflix", "amazon", "microsoft", "apple", "google",
          "linkedin", "instagram", "chase", "hdfc", "bank"]
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def safe_static_analysis(url):
    """Offline breakdown of a URL. No network calls -> always safe."""
    u = url if re.match(r"^https?://", url, re.I) else "http://" + url
    m = re.match(r"^(https?)://([^/:?#]+)([^?#]*)(\?[^#]*)?", u, re.I)
    scheme = (m.group(1) if m else "").lower()
    host = (m.group(2) if m else "").lower()
    path = m.group(3) if m else ""
    query = m.group(4) if m and m.group(4) else ""

    flags = []
    is_ip = bool(IP_RE.match(host))
    if is_ip:
        flags.append("Uses a raw IP address instead of a domain name")
    if scheme == "http":
        flags.append("Not encrypted (http, not https)")
    if any(host.endswith(t) for t in SUSPICIOUS_TLDS):
        flags.append("Uses a suspicious top-level domain")
    if any(s in host for s in SHORTENERS):
        flags.append("Is a shortened link that hides its real destination")
    if "@" in u.split("//", 1)[-1]:
        flags.append("Contains an '@' redirect trick")
    if not is_ip and host.count(".") >= 3:
        flags.append("Has an unusually long chain of subdomains")
    for b in BRANDS:
        if b[:4] in host and b not in host and re.search(r"[\d-]", host):
            flags.append(f"Domain looks like a misspelled version of '{b}'")
            break

    return {
        "url": url, "scheme": scheme, "host": host, "is_ip_address": is_ip,
        "path": path, "query": query, "suspicious_flags": flags,
        "risk": "high" if (is_ip or len(flags) >= 2) else ("medium" if flags else "low"),
    }


def _detonate_self_hosted(url):
    """Call a self-hosted sandbox micro-service (see sandbox/). Returns report or None."""
    try:
        r = requests.get(f"{SANDBOX_URL}/open", params={"url": url}, timeout=60)
        r.raise_for_status()
        d = r.json()
        return {
            "engine": "self-hosted sandbox",
            "final_url": d.get("final_url", url),
            "title": d.get("title", ""),
            "redirects": d.get("redirects", []),
            "screenshot": d.get("screenshot", ""),   # data URL or link
            "verdict": d.get("verdict", "unknown"),
            "detail": d.get("detail", ""),
        }
    except Exception as e:
        return {"engine": "self-hosted sandbox", "verdict": "error", "detail": str(e)[:160]}


def _detonate_urlscan(url, max_wait=35):
    """Submit the URL to urlscan.io, wait for the sandbox scan, and parse it."""
    try:
        # "unlisted" works on free accounts; "private" needs a paid plan.
        sub = requests.post("https://urlscan.io/api/v1/scan/",
                            headers={"API-Key": URLSCAN_KEY},
                            json={"url": url, "visibility": "unlisted"}, timeout=20)
        if sub.status_code != 200:
            msg = ""
            try:
                j = sub.json()
                msg = j.get("message") or j.get("description") or ""
            except Exception:
                pass
            # A 400 usually means the domain doesn't resolve (e.g. a fake test domain).
            return {"engine": "urlscan.io", "verdict": "unavailable",
                    "detail": f"urlscan couldn't scan this link: {msg or ('HTTP ' + str(sub.status_code))}. "
                              "The domain may not exist or is blocked."}
        uuid = sub.json().get("uuid")
        result_api = f"https://urlscan.io/api/v1/result/{uuid}/"

        # The scan runs asynchronously; poll until the result is ready.
        deadline = time.time() + max_wait
        data = None
        while time.time() < deadline:
            time.sleep(4)
            g = requests.get(result_api, headers={"API-Key": URLSCAN_KEY}, timeout=20)
            if g.status_code == 200:
                data = g.json()
                break

        if not data:
            return {"engine": "urlscan.io", "verdict": "pending",
                    "detail": "scan submitted; results not ready yet",
                    "result_page": f"https://urlscan.io/result/{uuid}/"}

        page = data.get("page", {})
        task = data.get("task", {})
        lists = data.get("lists", {})
        verdicts = data.get("verdicts", {}).get("overall", {})
        malicious = bool(verdicts.get("malicious"))
        return {
            "engine": "urlscan.io",
            "final_url": page.get("url", url),
            "final_domain": page.get("domain", ""),
            "title": page.get("title", ""),
            "server": page.get("server", ""),
            "redirected": task.get("url", url) != page.get("url", url),
            "domains_contacted": len(lists.get("domains", []) or []),
            "screenshot": task.get("screenshotURL") or f"https://urlscan.io/screenshots/{uuid}.png",
            "result_page": f"https://urlscan.io/result/{uuid}/",
            "verdict": "malicious" if malicious else "clean",
            "score": verdicts.get("score", 0),
        }
    except Exception as e:
        return {"engine": "urlscan.io", "verdict": "error", "detail": str(e)[:160]}


def _summarize(static, dynamic):
    """One plain-English sentence about what would have happened."""
    if not dynamic:
        if static["risk"] == "high":
            return "This link looks dangerous based on its structure. A live sandbox scan (add an API key) would confirm what it does."
        return "No live detonation was run. Based on its structure alone, this link looks " + static["risk"] + " risk."
    v = dynamic.get("verdict")
    if v == "malicious":
        return "The sandbox opened this link and flagged it as MALICIOUS. Had you clicked it, you would likely have reached a harmful or fake page."
    if v == "clean":
        dest = dynamic.get("final_domain") or dynamic.get("final_url", "")
        return f"The sandbox opened this link safely. It led to {dest} and showed no obviously malicious behaviour."
    if v == "pending":
        return "The link was sent to the sandbox; the scan is still running. Check the result page in a moment."
    return "The sandbox could not complete the analysis."


def detonate_url(url):
    """Full report: always-safe static analysis + (if configured) live detonation."""
    static = safe_static_analysis(url)

    dynamic = None
    if SANDBOX_URL:
        dynamic = _detonate_self_hosted(url)
    elif URLSCAN_KEY:
        dynamic = _detonate_urlscan(url)

    report = {"url": url, "static_analysis": static, "dynamic_analysis": dynamic,
              "summary": _summarize(static, dynamic)}
    if dynamic is None:
        report["note"] = ("Live detonation not configured. Set URLSCAN_API_KEY for "
                          "urlscan.io, or SANDBOX_URL for a self-hosted sandbox, to "
                          "actually open the link in isolation.")
    return report
