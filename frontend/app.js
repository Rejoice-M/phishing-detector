// app.js
// Purpose: the dashboard's behaviour.
//   - switches between the "URL" and "email" tabs
//   - sends the URL (JSON) or the .eml file (upload) to the API
//   - draws the score, risk meter and findings from the response
// Security note: everything from the API is put on the page with textContent, never innerHTML,
// because finding reasons can contain text taken from the URL or email being analysed.

const $ = (id) => document.getElementById(id);

// Friendly names for the check IDs the API returns
const LABELS = {
  https: "HTTPS", ip_address: "IP address", length: "URL length", subdomains: "Subdomains",
  at_symbol: "@ symbol", typosquatting: "Lookalike domain", domain_age: "Domain age",
  safe_browsing: "Google Safe Browsing", spf: "SPF", dkim: "DKIM", dmarc: "DMARC",
  reply_to: "Reply-To", display_name: "Display name", sender_domain: "Sender domain",
  urgency: "Urgency wording", link_mismatch: "Link mismatch", links: "Links in the email",
};

// ---------- Tabs ----------

const tabButtons = document.querySelectorAll(".tab");
const panels = { url: $("panel-url"), email: $("panel-email") };

function showTab(name) {
  tabButtons.forEach((button) => {
    const active = button.dataset.tab === name;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
  });
  Object.entries(panels).forEach(([key, panel]) => { panel.hidden = key !== name; });
  hideResult();
  clearStatus();
}

tabButtons.forEach((button) => {
  button.addEventListener("click", () => showTab(button.dataset.tab));
});

// ---------- Status messages ----------

function setStatus(message, isError = false) {
  const box = $("status");
  box.textContent = message;
  box.classList.toggle("error", isError);
  box.hidden = false;
}

function clearStatus() { $("status").hidden = true; }
function hideResult() { $("result").hidden = true; }

// ---------- Talking to the API ----------

async function request(path, options) {
  let response;
  try {
    response = await fetch(path, options);
  } catch {
    throw new Error("Could not reach the server. Make sure it is running.");
  }

  let data = null;
  try { data = await response.json(); } catch { /* the reply was not JSON */ }

  if (!response.ok) {
    const detail = data && typeof data.detail === "string" ? data.detail : null;
    throw new Error(detail || `The request failed (HTTP ${response.status}).`);
  }
  return data;
}

async function run(button, busyText, idleText, task) {
  hideResult();
  button.disabled = true;
  button.textContent = busyText;
  setStatus("Analyzing... lookups can take a few seconds.");
  try {
    await task();
    clearStatus();
  } catch (error) {
    setStatus(error.message || "Something went wrong. Please try again.", true);
  } finally {
    button.disabled = false;
    button.textContent = idleText;
  }
}

// ---------- Drawing the result ----------

function fillList(list, findings, flagged) {
  list.replaceChildren();
  findings.forEach((finding) => {
    const item = document.createElement("li");
    item.className = "finding";
    if (flagged) item.classList.add(finding.points >= 35 ? "sev-high" : "sev-medium");

    const head = document.createElement("div");
    head.className = "finding-head";
    const name = document.createElement("strong");
    name.textContent = LABELS[finding.check] || finding.check;
    head.appendChild(name);
    if (flagged) {
      const points = document.createElement("span");
      points.className = "points";
      points.textContent = `+${finding.points}`;
      head.appendChild(points);
    }

    const reason = document.createElement("p");
    reason.textContent = finding.reason;

    item.append(head, reason);
    list.appendChild(item);
  });
}

function renderResult(data, target) {
  const score = Math.max(0, Math.min(100, Number(data.score) || 0));
  const risk = ["low", "medium", "high"].includes(data.risk_level) ? data.risk_level : "low";
  const findings = Array.isArray(data.findings) ? data.findings : [];
  const flagged = findings.filter((f) => f.triggered).sort((a, b) => b.points - a.points);
  const passed = findings.filter((f) => !f.triggered);

  $("score").textContent = String(score);
  const badge = $("risk");
  badge.textContent = `${risk} risk`;
  badge.className = `badge ${risk}`;
  $("target").textContent = target;

  const fill = $("meter-fill");
  fill.className = `meter-fill ${risk}`;
  fill.style.width = `${score}%`;

  $("flag-count").textContent = `(${flagged.length})`;
  $("pass-count").textContent = `(${passed.length})`;
  $("no-flags").hidden = flagged.length > 0;
  fillList($("flagged"), flagged, true);
  fillList($("passed"), passed, false);

  $("result").hidden = false;
  $("result").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// ---------- Forms ----------

$("url-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = $("url-input").value.trim();
  if (!url) return;

  await run($("url-submit"), "Checking...", "Analyze", async () => {
    const data = await request("/analyze/url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    renderResult(data, data.url);
  });
});

$("email-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = $("email-input").files[0];
  if (!file) return;

  await run($("email-submit"), "Checking...", "Analyze", async () => {
    const body = new FormData();
    body.append("file", file);
    const data = await request("/analyze/email", { method: "POST", body });
    renderResult(data, data.filename || file.name);
  });
});

// Example buttons fill in the URL box and run the check
document.querySelectorAll(".chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    $("url-input").value = chip.dataset.url;
    $("url-form").requestSubmit();
  });
});
