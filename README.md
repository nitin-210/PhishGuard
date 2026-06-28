# 🛡️ PhishGuard

**An AI-powered phishing detection and safe link-detonation system** — usable as a web app *and* a browser extension that works directly inside Gmail and Outlook.

PhishGuard reads an email (sender, subject, body, links), uses a machine-learning model plus a rule safety net to decide whether it's phishing, checks the links against live threat-intelligence, and can safely "detonate" a suspicious link in a sandbox to show what it actually does — all with a plain-English explanation of *why*.

---

## ✨ Features

- **Explainable AI classifier** — a Logistic Regression model turns an email into 19 measurable clues and outputs a phishing probability with human-readable reasons.
- **Rule safety net** — high-confidence rules (raw-IP links, brand-impersonating domains, etc.) catch obvious phishing the model might miss.
- **Live link reputation** — checks each link with VirusTotal and urlscan.io.
- **Safe link detonation** — an offline structural analysis plus live sandboxing via urlscan.io, so risky links never open on your computer.
- **Web app** — paste a link, a domain, or a whole email and get a colour-coded verdict.
- **Gmail / Outlook extension** — a "Check email" button right inside your inbox.

## 🧠 How the AI works (in short)

The model can't read English, so each email is converted into **19 numeric clues** (URL, language, and sender signals). It's trained on labelled examples to learn a **weight** for each clue, then predicts a phishing probability for new emails. Because every clue has a weight, PhishGuard can explain which clues drove the decision. See `BUILD_LOG.md` and the project reports for the full story.

## 🚀 Quick start (local)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Build the dataset and train the model (one time)
python src/make_dataset.py
python src/train.py

# 3. Run the backend + web app
uvicorn src.api:app --reload
```

Open **http://localhost:8000/** in your browser.

*(Optional)* enable live link checks by setting free API keys before step 3:
```bash
# Windows PowerShell
$env:URLSCAN_API_KEY="your_key"; $env:VIRUSTOTAL_API_KEY="your_key"
```

## 🐳 Run with Docker (anywhere)

No Python setup needed — just Docker:

```bash
# Build the image (trains the model inside the image)
docker build -t phishguard .

# Run it
docker run -p 8000:8000 phishguard
```

Or with Docker Compose:
```bash
docker compose up --build
```

Then open **http://localhost:8000/**. To enable live detonation, pass your key:
```bash
docker run -p 8000:8000 -e URLSCAN_API_KEY=your_key phishguard
```

## 🧩 Browser extension (Gmail + Outlook)

1. Start the backend (local or Docker).
2. In Chrome, go to `chrome://extensions`, enable **Developer mode**, click **Load unpacked**, and select the `extension/` folder.
3. Open Gmail or Outlook on the web and click the **🛡️ Check email** button.

See `extension/README.md` for details.

## 📁 Project structure

```
PhishGuard/
├── src/
│   ├── make_dataset.py   # generates the labelled training data
│   ├── features.py       # turns an email into 19 numeric clues
│   ├── train.py          # trains + evaluates + saves the model
│   ├── predict.py        # scores an email + explains why
│   ├── rules.py          # rule-based safety net
│   ├── link_check.py     # VirusTotal / urlscan reputation
│   ├── detonate.py       # offline analysis + urlscan detonation
│   └── api.py            # FastAPI backend (serves the web UI too)
├── web/index.html        # the web application
├── extension/            # Chrome extension for Gmail / Outlook
├── sandbox/              # (attempted) self-hosted detonation sandbox + AWS Terraform
├── Dockerfile            # container build
├── docker-compose.yml
├── requirements.txt
└── BUILD_LOG.md          # detailed build journal
```

## ⚠️ Disclaimer

PhishGuard is an educational / portfolio project. The bundled model is trained on a small **synthetic** dataset, so its accuracy figures are optimistic; for real use, retrain on real datasets (PhishTank, Nazario corpus, Enron). Do **not** test it by visiting real malicious links — use the safe detonation feature, which opens links in an isolated sandbox.

## 📄 License

MIT — see [LICENSE](LICENSE).
