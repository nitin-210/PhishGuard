# PhishGuard Browser Extension (Gmail + Outlook)

A Chrome extension that adds a **"🛡️ Check email"** button inside Gmail and
Outlook on the web. Click it while reading an email and PhishGuard analyses the
sender, subject, body, and links right there, using your local backend.

## Before you start
The extension talks to your PhishGuard backend, so **the server must be running**:
```bash
uvicorn src.api:app --reload
```
(The backend now allows cross-origin requests, so the extension can reach it.)

## Install it (one time)
1. Open Chrome and go to **chrome://extensions**.
2. Turn on **Developer mode** (top-right toggle).
3. Click **Load unpacked**.
4. Select this `extension` folder
   (`...\AI Project\PhishGuard\extension`).
5. PhishGuard appears in your extensions list.

## Use it
1. Open **Gmail** (mail.google.com) or **Outlook** (outlook.live.com /
   outlook.office.com) and open any email.
2. Click the **🛡️ Check email** button in the bottom-right corner of the page.
3. A panel opens with the email already filled in (you can edit it). Click
   **Analyze this email** to see the verdict, reasons, and link results.

## Settings
Click the PhishGuard icon in Chrome's toolbar to set the **Backend URL**
(default `http://127.0.0.1:8000`). Change this if you later deploy the backend
to the cloud.

## Notes & limitations
- Gmail and Outlook change their page structure often, so the auto-extraction is
  best-effort. The panel fields are **editable**, so if something doesn't fill in
  correctly you can paste the email text manually and still analyse it.
- This is a developer/portfolio build loaded unpacked. Publishing to the Chrome
  Web Store (and a production cloud backend) would be a later step.
- For Outlook *desktop* or a fully official Gmail sidebar, the alternative is a
  Microsoft Office add-in / Google Workspace Add-on — documented as a future
  option in the project plan.
