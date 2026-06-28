# Self-Hosted Detonation Sandbox (optional / advanced)

This is the "each company runs its own isolated VM" version of link detonation.
Instead of sending suspicious links to urlscan.io, you run **this** small service
inside an isolated container, and the main PhishGuard backend calls it. The risky
link is opened **here**, in throwaway infrastructure — never on a real computer.

> You do NOT need this to use PhishGuard. The main app already detonates links
> safely via urlscan.io (just add a `URLSCAN_API_KEY`). Use this only if you want
> to control the sandbox yourself. It requires Docker.

## What it does
Exposes `GET /open?url=...`, which opens the URL in a headless Chromium browser
and returns the final address (after redirects), the page title, a screenshot,
and the redirect chain — as JSON.

## Run it with Docker (recommended)
```bash
cd sandbox
docker build -t phishguard-sandbox .
docker run --rm -p 9000:9000 phishguard-sandbox
```

## Point the main backend at it
Set an environment variable before starting the PhishGuard API, then start it:
```bash
# Windows PowerShell
$env:SANDBOX_URL="http://127.0.0.1:9000"
uvicorn src.api:app --reload
```
Now `/detonate` uses your sandbox instead of urlscan.io.

## Run without Docker (for quick testing)
```bash
pip install -r requirements.txt
playwright install --with-deps chromium
uvicorn sandbox_server:app --host 0.0.0.0 --port 9000
```

## SAFETY — read this
Opening live malicious links is genuinely risky. Run this sandbox only in an
environment that is:
- **disposable** — recreate the container after scans;
- **network-isolated** — no access to your real accounts or internal network;
- **least-privileged** — treat the VM as compromised after each use.

For production you would add: per-scan container recreation, outbound network
limits, resource caps, and a timeout/kill switch. This starter version is for
learning and demonstration.
