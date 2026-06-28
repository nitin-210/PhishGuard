"""
test_api.py
-----------
A tiny client that calls your running backend so you can see it work without
the browser. Start the server FIRST in another terminal:

    uvicorn src.api:app --reload

Then, in a second terminal:

    python src/test_api.py
"""

import requests

API = "http://127.0.0.1:8000/analyze"

samples = [
    {
        "sender": "PayPal Support <security@paypa1-security.com>",
        "subject": "[Action Required] Your account has been limited",
        "body": ("Dear Customer, unusual sign-in detected. Verify your password "
                 "immediately: http://192.168.10.5/login or your account is suspended."),
    },
    {
        "sender": "GitHub <notifications@github.com>",
        "subject": "New comment on your pull request",
        "body": "Hi Nitin, view it here: https://github.com/your/repo/pull/12",
    },
]

for e in samples:
    r = requests.post(API, json=e, timeout=60)
    data = r.json()
    print("=" * 60)
    print("Subject     :", e["subject"])
    print("Verdict     :", data.get("final_verdict"), f"({data.get('final_score')})")
    print("Model score :", data.get("model_score"))
    print("Reasons     :", data.get("reasons"))
    print("Links found :", data.get("links_found"))
    for lr in data.get("link_reputation", []):
        print(f"   - {lr['source']:11} {lr['verdict']:9} {lr['detail']}")
