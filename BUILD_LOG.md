# PhishGuard — Build Log (for the final report)

A running record of what was built, the decisions behind it, and the results.
Use this as raw material for your project report. Each phase adds a new section.

---

## Project summary

**Title:** PhishGuard — an AI-powered phishing-detection agent for email
**Goal:** Detect phishing emails (and, in later phases, safely analyse their links)
directly inside Gmail/Outlook, with plain-language explanations.
**Approach:** Build in phases. Phase 1 is the standalone machine-learning classifier.

---

## Phase 1 — The AI phishing classifier

**Status:** ✅ Complete
**Date:** June 2026

### 1.1 Objective
Build a model that takes an email (sender, subject, body) and outputs a phishing
probability plus the reasons for its decision.

### 1.2 Design decisions and why

| Decision | Choice | Reason |
|---|---|---|
| Algorithm | Logistic Regression | Simple, fast, runs on a laptop, and **explainable** (each feature has a weight), so we can tell the user *why* an email was flagged. |
| Approach | Hand-crafted features (not deep learning) | A beginner can understand and defend every feature; needs little data and no GPU. DistilBERT is a planned later upgrade. |
| Data | Synthetic starter dataset (240 emails) | Real corpora need accounts/large downloads. Synthetic data lets the full pipeline run on day one; swap in real data later without changing code. |
| Evaluation | Train/test split + 5-fold cross-validation | Honest measurement on data the model never trained on. |
| Key metric | **Recall** (alongside precision) | In security, missing a real phishing email (false negative) is worse than a false alarm. |

### 1.3 How it works (pipeline)

```
email (sender, subject, body)
      │
      ▼
features.py   → 18 numeric features (e.g. has_ip_url, num_urgency_words,
      │          sender_name_brand_mismatch, lookalike_brand_domain, ...)
      ▼
StandardScaler → put all features on the same scale
      │
      ▼
LogisticRegression → phishing probability (0–1)
      │
      ▼
verdict (PHISHING / SUSPICIOUS / LIKELY SAFE) + top reasons
```

### 1.4 The 18 features and the intuition behind them

*URL clues:* number of links, link uses a raw IP address, link uses a URL
shortener, "@" redirect trick in a link, many subdomains, suspicious top-level
domain (.top/.xyz/…), unusually long link.

*Language clues:* count of urgency words, threat words, credential-request words,
money/prize words, a generic greeting ("Dear Customer"), number of exclamation
marks, body length.

*Sender clues:* sender uses a free email provider, display name claims a brand the
domain doesn't match, sender domain contains digits/hyphens, domain looks like a
misspelled brand (e.g. `paypa1-security.com`).

### 1.5 Files written
- `src/make_dataset.py` — generates the 240-email starter dataset.
- `src/features.py` — converts an email into the 18 features (with explanations).
- `src/train.py` — trains, evaluates, and saves the model (scikit-learn).
- `src/predict.py` — scores a new email and lists the reasons.
- `README.md` — setup and run instructions.

### 1.6 Results

Two evaluations were run.

**(a) Reference check (numpy logistic regression, same features & data),** used to
validate the pipeline:

| Metric | Value |
|---|---|
| Accuracy | 1.000 |
| Precision | 1.000 |
| Recall | 1.000 |
| Test set | 60 emails (TN=31, FP=0, FN=0, TP=29) |

Top signals the model learned (higher = stronger phishing indicator):
`sender_domain_has_digit_or_hyphen`, `has_generic_greeting`,
`num_credential_words`, `num_urgency_words`, `num_threat_words`,
`sender_name_brand_mismatch`.

Demo emails: a spoofed-PayPal phishing mail scored **91.8%**; a real GitHub
notification scored **0.0%**.

**(b) scikit-learn version (`train.py`)** — actual run on the user's machine
(Logistic Regression, 25% held-out test set = 60 emails):

| Metric | Value |
|---|---|
| Accuracy | 1.000 |
| Precision | 1.000 |
| Recall | 1.000 |
| F1 score | 1.000 |
| 5-fold CV F1 | 1.000 (± 0.000) |

Confusion matrix (rows = true, cols = predicted):

|              | pred legit | pred phish |
|--------------|:----------:|:----------:|
| **true legit**  | 30 | 0 |
| **true phish**  | 0  | 30 |

Top signals the model learned (weight; higher = stronger phishing indicator):
`has_generic_greeting` (+0.86), `sender_domain_has_digit_or_hyphen` (+0.86),
`num_credential_words` (+0.84), `num_urgency_words` (+0.74),
`num_threat_words` (+0.69), `sender_name_brand_mismatch` (+0.65),
`body_length` (+0.49), `has_ip_url` (+0.46).

This confirms the pipeline is correct: the model learned exactly the clues a
human would use to spot phishing. The perfect score reflects the clean synthetic
data (see limitations) — the same code on real data will produce lower, more
realistic numbers.

### 1.7 Honest limitations (important for the report)
- The starter dataset is **synthetic and cleanly separable**, which is why scores
  are near-perfect. Real phishing is subtler; expect lower, more realistic numbers
  once real data is used — that is normal and is where the interesting work begins.
- Features are English-focused; multilingual/obfuscated attacks need more work
  (a strong future extension).
- The model sees only text + URL structure, not the *live* behaviour of a link —
  that's exactly what Phase 3 (safe detonation) adds.

### 1.8 Next step (Phase 2)
Wrap `score_email()` in a FastAPI endpoint and add live link-reputation checks
(VirusTotal, urlscan.io), combining the model score with real-world link data.

---

## Phase 2 — Backend API + link reputation

**Status:** ✅ Complete
**Date:** June 2026

### 2.1 Objective
Turn the Phase 1 model into a running web service that the future Gmail/Outlook
extension can call, and strengthen the decision with live link reputation data.

### 2.2 Design decisions and why

| Decision | Choice | Reason |
|---|---|---|
| Web framework | FastAPI + uvicorn | Modern, beginner-friendly, auto-generates interactive API docs at `/docs`. |
| Two opinions | AI model **and** link reputation | The model judges the text; VirusTotal/urlscan judge the links. Combining independent signals is more robust than either alone. |
| Threat-intel sources | VirusTotal + urlscan.io | Free tiers; industry-trusted; VirusTotal aggregates 90+ scanners, urlscan sandboxes the page. |
| Missing API keys | Skip gracefully, don't crash | The backend must run for anyone cloning the repo, even without keys. |
| Combine rule | A confirmed-malicious link forces PHISHING | Hard threat-intel evidence should override a softer text-only score. |

### 2.3 How it works

```
POST /analyze {sender, subject, body}
      │
      ├─► AI model (Phase 1)         → model_score + reasons (text)
      │
      ├─► extract links → VirusTotal + urlscan.io → link verdicts (live)
      │
      ▼
  combine: malicious link?  yes → PHISHING (override)
                            no  → use model verdict
      │
      ▼
  JSON: final_verdict, final_score, model_score, reasons, link_reputation
```

### 2.4 Files written
- `src/link_check.py` — queries VirusTotal & urlscan.io; safe fallback without keys.
- `src/api.py` — FastAPI app with `/health` and `/analyze`; loads the model once at startup.
- `src/test_api.py` — small client to exercise the API from a terminal.
- `.env.example` — template for the two API keys.
- `requirements.txt` — updated with fastapi, uvicorn, requests, pydantic.

### 2.5 Verification
Network-dependent code can't run in the build sandbox, so the non-network logic
was unit-checked with the real modules:
- URL extraction pulls both links from a test email correctly.
- With no API keys, link checks return `skipped` (no crash, no network call).
- `links_are_malicious()` returns True only when a source reports malicious.
- Combine logic confirmed: a bad link turns a 0.20 "safe" email into PHISHING (0.95);
  a clean email keeps the model's verdict.

On the user's machine: `uvicorn src.api:app --reload`, then open
`http://127.0.0.1:8000/docs` to test interactively.

### 2.6 Bug found during live testing, and the fix (great report material)

**Symptom:** A short test email — *"Verify now: http://192.168.0.5/login"* from a
spoofed PayPal sender — was scored **LIKELY SAFE (11%)**, despite an obvious
raw-IP link and a look-alike sender.

**Root cause:** The Phase 1 model had only ever seen *wordy* phishing (with a
"Dear Customer" greeting and several urgency/threat words). It had effectively
learned "long + wordy = phishing", so a short, blunt phishing email slipped
through. This is the synthetic-data limitation showing up in practice.

**Two-part fix:**
1. **More representative data.** `make_dataset.py` now generates three phishing
   styles — wordy, terse one-liners, and short payment/refund bait — plus short
   legitimate notes, so the model must rely on structural clues (sender domain,
   link type) rather than length.
2. **Rule-based safety net (`rules.py`).** Independent of the model, a few
   high-confidence rules can only *raise* suspicion: e.g. a raw-IP link plus a
   credential request, a look-alike domain asking for login, or an "@" redirect
   trick. This mirrors how real security products combine ML with rules.

**Before vs. after (same email):**

| | Before | After |
|---|---|---|
| Verdict | LIKELY SAFE | **PHISHING** |
| Model probability | 11% | 99.9% (retrained on varied data) |
| Rules fired | — | 3 critical rules |

A short *legitimate* note still scored 0.1% with no rules firing, confirming the
change did not cause false positives. Retrained metrics on the varied dataset
remained strong (accuracy/precision/recall = 1.000 on the held-out set;
expect lower, realistic numbers once real-world data is used).

**Lesson for the report:** models inherit the biases of their training data;
testing on realistic inputs exposes blind spots; and combining a model with a
rule layer produces a more trustworthy system than either alone.

### 2.8 Web interface
Added a user-facing web page (`web/index.html`) served by the API at `/`. The user
types or pastes an email and sees a clean, color-coded result card (verdict badge,
score meter, plain-English reasons, and per-link reputation chips) instead of raw
JSON. The developer JSON docs remain available at `/docs`.

### 2.10 Second weakness found during live testing (and fixed)

**Symptom:** A clear phishing email tested inside Gmail scored only **26% (LIKELY
SAFE)**, despite urgency/threat wording and a link to `paypa1-security.com`.

**Root cause:** The email was sent from the user's own Gmail (legitimate sender),
and the brand impersonation lived in a **body link**, not the sender. But the
look-alike/brand-impersonation features were computed only from the **sender's**
domain — so the impostor link in the body was never scored.

**Fix:** Added a new feature `link_impersonates_brand` that checks every body-link
domain for (a) brand name on a non-official domain (`microsoft-verify.info`) and
(b) digit/letter swaps (`paypa1-security.com`), plus a matching critical rule that
forces a PHISHING verdict. Verified: impostor domains are flagged while real ones
(`paypal.com`, `google.com`, `accounts.google.com`, `github.com`) and unrelated
domains (`heleketgateway.com`) are not — so no false positives.

**Lesson for the report:** phishing signals can hide anywhere in a message; a
feature that only inspects the sender misses attacks carried in the body. Testing
on realistic, self-addressed samples exposed this.

### 2.9 Next step (Phase 3)
Safe link detonation — open suspicious links in an isolated sandbox (urlscan first,
then a customer-hosted Docker sandbox) and report what the link actually does.

## Phase 3 — Safe link detonation

**Status:** ✅ Complete (urlscan path working; self-hosted sandbox scaffolded)
**Date:** June 2026

### 3.1 Objective
For a suspicious link, find out what it actually does — final destination after
redirects, page title, a screenshot, and a malicious/clean verdict — **without
the link ever opening on the user's computer.**

### 3.2 Design decisions and why

| Decision | Choice | Reason |
|---|---|---|
| Two layers | Offline static analysis + live detonation | Static analysis always runs (no key, no network, 100% safe); live detonation adds real behaviour when configured. |
| Live sandbox | urlscan.io (default) or a self-hosted sandbox | urlscan needs only an API key and carries zero local risk — ideal to start. The self-hosted option realises the "each company runs its own isolated VM" idea. |
| Never open locally | Detonation happens in urlscan / an isolated container | The whole point: the risky link must never touch a real machine. |
| Self-hosted = optional | Scaffolded with Docker, clearly marked advanced | A beginner can ship the urlscan version; the Docker sandbox is there for the report and for production-minded users. |

### 3.3 How it works
`POST /detonate {url}` returns:
- **static_analysis** (offline): scheme, host, is-IP, suspicious flags, risk level.
- **dynamic_analysis** (live, if configured): final URL, domain, title, redirect
  info, screenshot link, and verdict — from urlscan.io or the self-hosted sandbox.
- **summary**: one plain-English sentence ("The sandbox opened this link and
  flagged it as malicious…").

The web UI and the Gmail/Outlook extension both show a **"🔬 Detonate safely"**
button next to each found link.

### 3.4 Files written
- `src/detonate.py` — static analysis + urlscan detonation + self-hosted hook.
- `src/api.py` — new `POST /detonate` endpoint.
- `web/index.html`, `extension/content.js` — per-link "Detonate safely" button + report.
- `sandbox/` — optional self-hosted detonation sandbox: `sandbox_server.py`
  (Playwright headless browser), `Dockerfile`, `requirements.txt`, `README.md`.
- `.env.example` — added `SANDBOX_URL`.

### 3.5 Verification
Static analysis was run offline on real URLs:

| URL | Risk | Notes |
|---|---|---|
| `https://survale.com` | low | legitimate — correctly low |
| `https://www.google.com` | low | legitimate — correctly low |
| `http://192.168.0.5/login` | high | raw IP + not https |
| `http://paypa1-security.com/verify@secure` | high | look-alike brand + '@' trick |

A bug (an IP address counted as "many subdomains" because of its dots) was found
and fixed.

**Live detonation verified (urlscan.io).** With a free urlscan API key, detonating
a real URL (`https://example.com`) successfully opened it in urlscan's sandbox and
returned the result. Two issues were found and fixed along the way: (1) the code
requested "private" scans, which free urlscan accounts reject — changed to
"unlisted"; (2) urlscan returns HTTP 400 for domains that don't resolve (e.g. the
fabricated test domains), which now shows a friendly "couldn't scan — domain may
not exist" message instead of a raw error. The isolated-EC2 sandbox path is built
and deployed but its in-container browser was not finished debugging; urlscan is
the working live-detonation engine.

### 3.7 Production deployment — isolated EC2 detonation sandbox

**Objective:** open suspicious links on a disposable, network-isolated AWS EC2 so
that malware/viruses in a link cannot reach personal resources or servers, and
cannot even persist on the sandbox VM.

**Three layers of isolation:**
1. *Network isolation (protects your resources).* A dedicated VPC with no peering
   or VPN — so there is nothing internal to reach — plus a network ACL that denies
   all outbound traffic to private ranges (10/8, 172.16/12, 192.168/16), and a
   security group that only admits the backend's IP. The link can reach the public
   internet at most.
2. *Ephemeral containers (protect the VM).* Each link is opened in a brand-new
   container that is read-only, drops all capabilities, has no-new-privileges,
   strict CPU/RAM/PID limits and a timeout, then is destroyed (`--rm`). Nothing
   survives a scan.
3. *Disposable host (defence in depth).* The EC2 is treated as cattle and recycled
   (Auto Scaling / re-apply) so the VM itself is regularly rebuilt clean.

**Files (`sandbox/aws/`):**
- `detonate_once.py` + `Dockerfile.detonator` — the one-shot throwaway detonator.
- `dispatcher.py` — host service; spawns one hardened container per link; exposes
  the `/open` contract the backend already calls via `SANDBOX_URL`.
- `terraform/main.tf` + `variables.tf` — dedicated VPC, NACL, security group, IAM
  (SSM, so no inbound SSH), and the EC2 with IMDSv2 + encrypted disk.
- `user-data.sh` — first-boot provisioning (Docker, build image, run dispatcher).
- `README.md` — architecture diagram, deploy/teardown steps, and honest limits.

**Verification:** Python (`detonate_once.py`, `dispatcher.py`) compiles; `user-data.sh`
passes `bash -n`; `main.tf` brace/bracket-balanced with all 11 resources present
and reformatted to valid multi-line HCL. Live AWS apply is a user step (needs an
AWS account); `terraform validate`/`apply` will confirm end-to-end.

**Honest limits:** no sandbox is 100% escape-proof; this is defence in depth.
Stronger options: Firecracker microVMs / Fargate, egress filtering, and private
networking + IAM auth instead of an IP allow-list.

### 3.6 Project status
Phases 1–4 complete plus a production-grade isolated detonation sandbox: trained
explainable model + rules, backend API with live link reputation, safe link
detonation (urlscan + self-hosted + isolated EC2), a web UI, and a Gmail/Outlook
extension. Remaining optional work: real-data retraining, deploying the main
backend, and the official Google/Microsoft add-ons.

## Phase 4 — Browser extension (Gmail + Outlook)

**Status:** ✅ Complete (developer/unpacked build)
**Date:** June 2026

### 4.1 Objective
Let the user check the email they are reading, directly inside the Gmail or
Outlook web window, instead of copy-pasting into a separate page.

### 4.2 Design decisions and why

| Decision | Choice | Reason |
|---|---|---|
| Extension type | Chrome extension (Manifest V3) | Runs in the user's browser, so it can both inject UI into the Gmail/Outlook page **and** call the local `127.0.0.1` backend during development. |
| One extension, both mail apps | Content script matched to Gmail + Outlook domains | Same code covers both; only the page-scraping selectors differ. |
| Extraction robustness | Editable panel pre-filled by best-effort scraping | Gmail/Outlook HTML changes often; letting the user edit the fields means it still works if a selector misses. |
| Backend reachability | Added CORS to the API | Browsers block cross-origin calls by default; CORS lets the extension call `/analyze`. |
| Official add-on instead? | Deferred | Google Workspace Add-ons / Office add-ins run on the vendor's servers and can't reach `localhost`; they need a deployed backend. Noted as a production step. |

### 4.3 How it works
1. A content script adds a floating "🛡️ Check email" button to the page.
2. Clicking it reads the open email (sender/subject/body) via DOM selectors
   (Gmail: `h2.hP`, `span.gD`, `div.a3s`; Outlook: heading + `Message body`).
3. The email is shown in an editable panel; "Analyze" POSTs it to the backend.
4. The verdict, reasons, and link reputation render in the panel.

### 4.4 Files written (in `extension/`)
- `manifest.json` — extension config; matches Gmail + Outlook; permits the backend host.
- `content.js` — button, extraction, panel, and the call to `/analyze`.
- `panel.css` — styling for the injected button and panel (prefixed `pg-` to avoid clashes).
- `popup.html` / `popup.js` — toolbar popup to set the backend URL (stored via `chrome.storage`).
- `README.md` — load-unpacked install and usage instructions.

Backend changes (`src/api.py`): added CORS middleware and a flexible input mode
so `/analyze` also accepts a pasted link, domain, or raw email (`text` field).
The web UI (`web/index.html`) gained a "paste anything" quick-check box.

### 4.5 Verification
- `manifest.json` validated as JSON; `content.js` and `popup.js` pass `node --check`.
- Input-parsing logic unit-checked: bare domains, full URLs, and raw `From:/Subject:`
  emails are each handled correctly.
- Live in-browser testing (loading unpacked in Chrome on real Gmail/Outlook) is a
  manual step for the user, since it needs a browser + signed-in mail account.

### 4.6 Status of Phase 5 (Outlook)
Covered by the same extension (Outlook web domains are in the manifest). A separate
native Office add-in remains an optional future enhancement.
