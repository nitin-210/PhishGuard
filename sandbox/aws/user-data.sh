#!/bin/bash
# Provisions the isolated EC2 sandbox on first boot (Amazon Linux 2023).
# Installs Docker, builds the throwaway detonator image, and runs the dispatcher.
set -euxo pipefail

dnf update -y
dnf install -y docker python3-pip
systemctl enable --now docker
pip3 install --no-cache-dir fastapi "uvicorn[standard]"

APP=/opt/phishguard
mkdir -p "$APP/detonator"

# --- one-shot detonator that runs inside each throwaway container ----------
cat > "$APP/detonator/detonate_once.py" <<'PYEOF'
import sys, json, base64
def main():
    if len(sys.argv) < 2:
        print(json.dumps({"verdict":"error","detail":"no url"})); return
    url = sys.argv[1]
    from playwright.sync_api import sync_playwright
    redirects=[]
    try:
        with sync_playwright() as p:
            b=p.chromium.launch(args=["--no-sandbox","--disable-dev-shm-usage"])
            c=b.new_context(ignore_https_errors=True); pg=c.new_page()
            pg.on("response", lambda r: redirects.append(r.url) if 300<=r.status<400 else None)
            pg.goto(url, wait_until="domcontentloaded", timeout=20000)
            fu=pg.url; ti=pg.title(); shot=pg.screenshot(type="png")
            pw=pg.query_selector("input[type=password]") is not None
            b.close()
        print(json.dumps({"final_url":fu,"title":ti,"redirects":[r for r in redirects if r],
            "asks_for_password":pw,"screenshot":"data:image/png;base64,"+base64.b64encode(shot).decode(),
            "verdict":"suspicious" if pw else "unknown","detail":"ephemeral isolated container"}))
    except Exception as e:
        print(json.dumps({"verdict":"error","detail":str(e)[:200]}))
main()
PYEOF

cat > "$APP/detonator/Dockerfile" <<'DOCKEREOF'
FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy
WORKDIR /app
RUN pip install --no-cache-dir playwright && python -m playwright install chromium
ENV HOME=/tmp
COPY detonate_once.py .
ENTRYPOINT ["python","detonate_once.py"]
DOCKEREOF

docker build -t phishguard-detonator "$APP/detonator"

# --- dispatcher: one fresh hardened container per link ---------------------
cat > "$APP/dispatcher.py" <<'PYEOF'
import json, subprocess
from fastapi import FastAPI
app=FastAPI()
IMAGE="phishguard-detonator"; TIMEOUT=60
FLAGS=["--rm","--network","bridge","--shm-size=512m","--memory=1200m","--cpus=1.0",
       "--pids-limit=512","--security-opt","no-new-privileges","--cap-drop=ALL","-e","HOME=/tmp"]
@app.get("/health")
def health(): return {"status":"ok"}
@app.get("/open")
def open_url(url:str):
    try:
        p=subprocess.run(["docker","run",*FLAGS,IMAGE,url],capture_output=True,text=True,timeout=TIMEOUT)
        out=(p.stdout or "").strip()
        if not out: return {"verdict":"error","detail":(p.stderr or "no output")[:200]}
        return json.loads(out.splitlines()[-1])
    except subprocess.TimeoutExpired:
        return {"verdict":"timeout","detail":"container killed after time limit"}
    except Exception as e:
        return {"verdict":"error","detail":str(e)[:200]}
PYEOF

# --- run the dispatcher as a service on port 9000 --------------------------
cat > /etc/systemd/system/phishguard-dispatcher.service <<EOF
[Unit]
Description=PhishGuard Sandbox Dispatcher
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=$APP
ExecStart=/usr/bin/python3 -m uvicorn dispatcher:app --host 0.0.0.0 --port 9000
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now phishguard-dispatcher
