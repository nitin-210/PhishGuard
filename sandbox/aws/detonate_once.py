"""
detonate_once.py  (runs INSIDE a throwaway container)
-----------------------------------------------------
Opens ONE url in a headless browser, prints a JSON report to stdout, and exits.
The container that runs this is created fresh for each link and destroyed
immediately after (docker run --rm), so nothing the link does can persist.

Usage (inside the container):  python detonate_once.py "<url>"
"""

import sys
import json
import base64


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"verdict": "error", "detail": "no url given"}))
        return
    url = sys.argv[1]

    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        print(json.dumps({"verdict": "error", "detail": f"playwright missing: {e}"}))
        return

    redirects = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.on("response", lambda r: redirects.append(r.url)
                    if 300 <= r.status < 400 else None)
            page.goto(url, wait_until="domcontentloaded", timeout=20000)

            final_url = page.url
            title = page.title()
            shot = page.screenshot(type="png")
            # Cheap phishing signal: a password field on the landing page.
            has_pw = page.query_selector("input[type=password]") is not None
            browser.close()

        print(json.dumps({
            "final_url": final_url,
            "title": title,
            "redirects": [r for r in redirects if r],
            "asks_for_password": has_pw,
            "screenshot": "data:image/png;base64," + base64.b64encode(shot).decode(),
            "verdict": "suspicious" if has_pw else "unknown",
            "detail": "Opened in an ephemeral, isolated container.",
        }))
    except Exception as e:
        print(json.dumps({"verdict": "error", "detail": str(e)[:200]}))


if __name__ == "__main__":
    main()
