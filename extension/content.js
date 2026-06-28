/*
 * PhishGuard content script
 * -------------------------
 * Runs inside the Gmail / Outlook web page. It:
 *   1. adds a floating "Check email" button,
 *   2. reads the email that's currently open on screen,
 *   3. sends it to your PhishGuard backend (/analyze),
 *   4. shows the verdict in a panel - all without leaving the inbox.
 *
 * Note: Gmail/Outlook change their HTML often, so the extraction below is
 * best-effort. The panel shows the extracted text in EDITABLE boxes, so even
 * if a selector misses, you can paste/fix the content and still analyse it.
 */

const DEFAULT_BACKEND = "http://127.0.0.1:8000";

function getBackend() {
  return new Promise((resolve) => {
    try {
      chrome.storage.sync.get({ backend: DEFAULT_BACKEND }, (v) =>
        resolve((v && v.backend) || DEFAULT_BACKEND)
      );
    } catch (e) {
      resolve(DEFAULT_BACKEND);
    }
  });
}

const isGmail = location.hostname.includes("mail.google.com");

/* ---------- Email extraction ---------- */
function extractGmail() {
  const subject = (document.querySelector("h2.hP") || {}).innerText || "";
  let sender = "";
  const g = document.querySelector("span.gD, span[email]");
  if (g) {
    const email = g.getAttribute("email");
    const name = g.getAttribute("name") || g.innerText || "";
    sender = email ? `${name} <${email}>` : name;
  }
  let body = "";
  document.querySelectorAll("div.a3s").forEach((el) => (body += el.innerText + "\n"));
  return { sender, subject, body: body.trim() };
}

function extractOutlook() {
  let subject = "";
  const h =
    document.querySelector('[role="main"] [role="heading"]') ||
    document.querySelector('span[role="heading"]');
  if (h) subject = h.innerText || "";
  const bodyEl =
    document.querySelector('div[aria-label="Message body"]') ||
    document.querySelector('[role="document"]');
  const body = bodyEl ? bodyEl.innerText.trim() : "";
  let sender = "";
  const s = document.querySelector('span[title*="@"], span[email]');
  if (s) sender = s.getAttribute("email") || s.getAttribute("title") || s.innerText || "";
  return { sender, subject, body };
}

function extractEmail() {
  try {
    return isGmail ? extractGmail() : extractOutlook();
  } catch (e) {
    return { sender: "", subject: "", body: "" };
  }
}

/* ---------- UI ---------- */
function el(tag, cls, html) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html != null) e.innerHTML = html;
  return e;
}

let panel;

function buildPanel() {
  panel = el("div", "pg-panel");
  panel.innerHTML = `
    <div class="pg-head">
      <span class="pg-logo">🛡️ PhishGuard</span>
      <span class="pg-close" id="pg-close">✕</span>
    </div>
    <div class="pg-body">
      <label class="pg-lbl">From</label>
      <input id="pg-sender" class="pg-in" />
      <label class="pg-lbl">Subject</label>
      <input id="pg-subject" class="pg-in" />
      <label class="pg-lbl">Body</label>
      <textarea id="pg-bodytext" class="pg-in pg-ta"></textarea>
      <button id="pg-run" class="pg-btn">Analyze this email</button>
      <div id="pg-loading" class="pg-muted" style="display:none">Analyzing…</div>
      <div id="pg-out"></div>
    </div>`;
  document.body.appendChild(panel);
  panel.querySelector("#pg-close").onclick = () => (panel.style.display = "none");
  panel.querySelector("#pg-run").onclick = runAnalysis;
}

function openPanel() {
  if (!panel) buildPanel();
  const d = extractEmail();
  panel.querySelector("#pg-sender").value = d.sender || "";
  panel.querySelector("#pg-subject").value = d.subject || "";
  panel.querySelector("#pg-bodytext").value = d.body || "";
  panel.querySelector("#pg-out").innerHTML = "";
  panel.style.display = "block";
}

async function runAnalysis() {
  const out = panel.querySelector("#pg-out");
  const loading = panel.querySelector("#pg-loading");
  out.innerHTML = "";
  loading.style.display = "block";
  const payload = {
    sender: panel.querySelector("#pg-sender").value,
    subject: panel.querySelector("#pg-subject").value,
    body: panel.querySelector("#pg-bodytext").value,
  };
  const backend = await getBackend();
  try {
    const res = await fetch(backend + "/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    loading.style.display = "none";
    if (data.error) {
      out.innerHTML = `<div class="pg-err">${data.error}</div>`;
      return;
    }
    renderResult(out, data);
  } catch (e) {
    loading.style.display = "none";
    out.innerHTML = `<div class="pg-err">Couldn't reach the backend at ${backend}. Make sure the server is running (uvicorn src.api:app --reload) and the URL is set in the extension popup.</div>`;
  }
}

function renderResult(out, d) {
  const score = Math.round((d.final_score || 0) * 100);
  let cls = "pg-safe",
    msg = "This email looks safe.";
  if (d.final_verdict === "PHISHING") {
    cls = "pg-phish";
    msg = "Very likely phishing. Do not click its links.";
  } else if (d.final_verdict === "SUSPICIOUS") {
    cls = "pg-susp";
    msg = "This email is suspicious. Be careful.";
  }
  let reasons = (d.reasons || []).map((r) => `<li>${r}</li>`).join("");
  if (!reasons) reasons = "<li>No strong phishing signals found.</li>";

  let links = "";
  (d.links_found || []).forEach((u) => {
    const reps = (d.link_reputation || [])
      .filter((x) => x.url === u)
      .map((x) => `<span class="pg-chip pg-${x.verdict}">${x.source}: ${x.verdict}</span>`)
      .join(" ");
    links += `<div class="pg-link"><div class="pg-url">${u}</div><div>${reps}</div>
      <button class="pg-det" data-url="${encodeURIComponent(u)}">🔬 Detonate safely</button>
      <div class="pg-detout"></div></div>`;
  });

  out.innerHTML = `
    <div class="pg-verdict ${cls}">
      <span class="pg-badge">${d.final_verdict}</span>
      <span>${msg}</span>
      <span class="pg-pct">${score}% risk</span>
    </div>
    <div class="pg-muted">AI phishing score: ${Math.round((d.model_prob || 0) * 100)}% (0% = safe, 100% = definitely phishing)${
    d.rule_hits && d.rule_hits.length ? ` · ${d.rule_hits.length} rule(s) triggered` : ""
  }</div>
    <div class="pg-sec">Why</div>
    <ul class="pg-reasons">${reasons}</ul>
    ${links ? `<div class="pg-sec">Links found</div>${links}` : ""}`;

  out.querySelectorAll(".pg-det").forEach((b) => (b.onclick = () => pgDetonate(b)));
}

async function pgDetonate(btn) {
  const url = decodeURIComponent(btn.getAttribute("data-url"));
  const box = btn.parentElement.querySelector(".pg-detout");
  btn.disabled = true;
  btn.textContent = "Detonating…";
  box.innerHTML = "";
  const backend = await getBackend();
  try {
    const res = await fetch(backend + "/detonate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const d = await res.json();
    const s = d.static_analysis || {};
    const dy = d.dynamic_analysis;
    let flags = (s.suspicious_flags || []).map((f) => `<li>${f}</li>`).join("");
    if (!flags) flags = "<li>No structural red flags.</li>";
    let dyn = "";
    if (dy) {
      dyn = `<div class="pg-muted" style="margin-top:6px">Sandbox (${dy.engine}): <b>${dy.verdict}</b>${
        dy.final_domain ? " · " + dy.final_domain : ""
      }</div>${dy.screenshot ? `<div><a href="${dy.screenshot}" target="_blank">Screenshot ↗</a></div>` : ""}${
        dy.result_page ? `<div><a href="${dy.result_page}" target="_blank">Full report ↗</a></div>` : ""
      }`;
    } else if (d.note) {
      dyn = `<div class="pg-muted" style="margin-top:6px">${d.note}</div>`;
    }
    box.innerHTML = `<div class="pg-deto"><div style="font-size:12px;margin-bottom:4px">${d.summary || ""}</div>
      <div class="pg-muted">risk: <b>${s.risk}</b></div>
      <ul class="pg-reasons" style="margin-top:4px">${flags}</ul>${dyn}</div>`;
  } catch (e) {
    box.innerHTML = `<div class="pg-err">Couldn't reach the backend.</div>`;
  }
  btn.disabled = false;
  btn.textContent = "🔬 Detonate safely";
}

/* ---------- Floating button ---------- */
function addButton() {
  if (document.getElementById("pg-fab")) return;
  const fab = el("div", "pg-fab", "🛡️ Check email");
  fab.id = "pg-fab";
  fab.onclick = openPanel;
  document.body.appendChild(fab);
}

// Gmail/Outlook are single-page apps that rebuild the DOM; keep the button alive.
addButton();
setInterval(addButton, 3000);
