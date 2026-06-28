"""
dispatcher.py  (runs on the isolated EC2 host)
----------------------------------------------
This is the service the main PhishGuard backend talks to (set SANDBOX_URL to
this machine). For every link, it launches a BRAND-NEW, locked-down container
that opens the link and then is destroyed. Nothing carries over between links,
and the link never runs anywhere except inside that disposable container.

It exposes the same contract the backend expects:
    GET /open?url=...   ->  { final_url, title, screenshot, verdict, ... }

Start it:  uvicorn dispatcher:app --host 0.0.0.0 --port 9000
"""

import json
import shlex
import subprocess

from fastapi import FastAPI

app = FastAPI(title="PhishGuard Sandbox Dispatcher", version="1.0")

IMAGE = "phishguard-detonator"
RUN_TIMEOUT = 60  # seconds; the container is killed if it runs longer

# Hardening flags applied to EVERY detonation container:
#   --rm                     destroy the container as soon as it exits
#   --network bridge         internet access to open the link, but (because this
#                            EC2 lives in a dedicated VPC with no internal routes)
#                            no path to any of your private resources
#   --read-only + tmpfs      no persistent writes; scratch space is in-memory only
#   --memory/--cpus/--pids   resource caps so a malicious page can't exhaust the host
#   --security-opt / --cap-drop  shrink the attack surface for container escape
HARD_FLAGS = [
    "--rm",
    "--network", "bridge",
    "--shm-size=512m",          # Chromium needs shared memory to render
    "--memory=1200m",
    "--cpus=1.0",
    "--pids-limit=512",
    "--security-opt", "no-new-privileges",
    "--cap-drop=ALL",
    "-e", "HOME=/tmp",
]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/open")
def open_url(url: str):
    cmd = ["docker", "run", *HARD_FLAGS, IMAGE, url]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=RUN_TIMEOUT)
        out = (proc.stdout or "").strip()
        if not out:
            return {"verdict": "error",
                    "detail": (proc.stderr or "no output from container")[:200]}
        # The detonator prints one JSON line; take the last line to be safe.
        return json.loads(out.splitlines()[-1])
    except subprocess.TimeoutExpired:
        return {"verdict": "timeout",
                "detail": "detonation exceeded the time limit; container was killed"}
    except Exception as e:
        return {"verdict": "error", "detail": str(e)[:200]}
