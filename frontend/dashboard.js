/**
 * dashboard.js — Cyber Ultron v2 Frontend
 * JWT-authenticated, real-time dashboard with Chart.js visualizations.
 */

const API = "";  // Same origin — backend serves frontend

// ── Auth ───────────────────────────────────────────────────────────────────────
const token = localStorage.getItem("cy_token");
const cyUser = localStorage.getItem("cy_user") || "admin";

if (!token) {
  window.location.href = "/";
}

function logout() {
  localStorage.removeItem("cy_token");
  localStorage.removeItem("cy_user");
  window.location.href = "/";
}

// Set username in navbar
document.getElementById("nav-user").textContent = `👤 ${cyUser.toUpperCase()}`;

// ── API helper ─────────────────────────────────────────────────────────────────
async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`,
      ...opts.headers
    },
    ...opts
  });
  if (res.status === 401) {
    logout();
    return null;
  }
  return res.ok ? res.json() : null;
}

// ── State ──────────────────────────────────────────────────────────────────────
let barChart = null;
let pieChart = null;
let knownAlertIds = new Set();
let isAnalyzing = false;
let refreshTimer = null;

// ── Init ───────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  refreshAll();
  refreshTimer = setInterval(refreshAll, 8000);
});

async function refreshAll() {
  await Promise.allSettled([
    loadStats(),
    loadLogs(),
    loadAlerts(),
    loadBlocked()
  ]);
}

// ── Stats ──────────────────────────────────────────────────────────────────────
async function loadStats() {
  const data = await api("/stats");
  if (!data) return;

  document.getElementById("s-logs").textContent    = data.total_logs;
  document.getElementById("s-alerts").textContent  = data.total_alerts;
  document.getElementById("s-blocked").textContent = data.total_blocked;

  const dot   = document.getElementById("status-dot");
  const label = document.getElementById("status-label");
  const pill  = document.getElementById("status-pill");

  if (data.status === "THREAT_DETECTED") {
    dot.className   = "status-dot threat";
    label.textContent = "THREAT DETECTED";
    label.style.color = "var(--red)";
  } else {
    dot.className   = "status-dot normal";
    label.textContent = "SYSTEMS NOMINAL";
    label.style.color = "var(--green)";
  }
}

// ── Logs Table + Bar Chart ─────────────────────────────────────────────────────
async function loadLogs() {
  const data = await api("/logs?limit=150");
  if (!data) return;

  const logs = data.logs || [];
  document.getElementById("log-count").textContent = `${logs.length} entries · auto-refresh 8s`;

  renderLogsTable(logs);
  updateBarChart(logs);
  updatePieChart(logs);
}

function renderLogsTable(logs) {
  const tbody = document.getElementById("logs-body");
  if (!logs.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty">No logs. Run the simulator or upload a file.</td></tr>`;
    return;
  }

  tbody.innerHTML = logs.slice(0, 80).map(log => {
    const isHighReq   = log.requests > 200;
    const isHighLogin = log.login_attempts > 10;
    const sus         = isHighReq || isHighLogin;
    const rowCls      = sus ? "row-sus" : "";

    const barPct = Math.min((log.requests / 600) * 100, 100);
    const barCls = log.requests > 400 ? "bar-bad" : log.requests > 200 ? "bar-warn" : "bar-ok";

    const srcBadge = log.source === "uploaded"
      ? `<span class="badge badge-upload">uploaded</span>`
      : `<span class="badge badge-sim">simulated</span>`;

    const statusBadge = sus
      ? `<span class="badge badge-sus">⚠ SUSPICIOUS</span>`
      : `<span class="badge badge-normal">✓ NORMAL</span>`;

    return `<tr class="${rowCls}">
      <td class="cell-ip">${esc(log.ip)}</td>
      <td>
        <div class="req-bar">
          <div class="bar-track"><div class="bar-fill ${barCls}" style="width:${barPct}%"></div></div>
          <span>${log.requests}</span>
        </div>
      </td>
      <td>${log.login_attempts}</td>
      <td>${srcBadge}</td>
      <td class="cell-ts">${fmtTime(log.timestamp)}</td>
      <td>${statusBadge}</td>
    </tr>`;
  }).join("");
}

// ── Alerts ─────────────────────────────────────────────────────────────────────
async function loadAlerts() {
  const data = await api("/alerts");
  if (!data) return;

  const alerts = data.alerts || [];
  document.getElementById("alert-count").textContent = `${alerts.length} alerts`;

  const container = document.getElementById("alerts-body");
  if (!alerts.length) {
    container.innerHTML = `<div class="empty">No alerts. System is clean.</div>`;
    return;
  }

  // Detect new alerts for toast notifications
  const newOnes = alerts.filter(a => !knownAlertIds.has(a.id));
  if (newOnes.length && knownAlertIds.size > 0) {
    newOnes.slice(0, 3).forEach(a => showToast(`⚠ ${a.ip} — ${a.severity}`, "t-threat"));
  }
  alerts.forEach(a => knownAlertIds.add(a.id));

  container.innerHTML = alerts.slice(0, 40).map(a => `
    <div class="alert-card sev-${a.severity}">
      <div class="alert-top">
        <span class="alert-ip">${esc(a.ip)}</span>
        <span class="sev-pill sev-${a.severity}">${a.severity}</span>
      </div>
      <div class="alert-reason">${esc(a.reason)}</div>
      <div class="alert-time">${fmtTime(a.timestamp)}</div>
    </div>
  `).join("");
}

// ── Blocked IPs ────────────────────────────────────────────────────────────────
async function loadBlocked() {
  const data = await api("/blocked");
  if (!data) return;

  const blocked = data.blocked_ips || [];
  document.getElementById("blocked-count").textContent = `${blocked.length} blocked`;

  const container = document.getElementById("blocked-body");
  if (!blocked.length) {
    container.innerHTML = `<div class="empty">No IPs blocked.</div>`;
    return;
  }

  container.innerHTML = blocked.map(b => `
    <div class="blocked-chip">
      <span>🚫</span>
      <span class="chip-ip">${esc(b.ip)}</span>
      <span class="chip-time">${fmtTime(b.blocked_at)}</span>
      <button class="btn-unblock" onclick="unblockIP('${esc(b.ip)}')">Unblock</button>
    </div>
  `).join("");
}

async function manualBlock(e) {
  e.preventDefault();
  const input = document.getElementById("block-ip-input");
  const ip = input.value.trim();
  if (!ip) return;

  const res = await api("/block-ip", {
    method: "POST",
    body: JSON.stringify({ ip, reason: "Manually blocked by admin" })
  });
  if (res) {
    showToast(res.message, res.success ? "t-ok" : "t-info");
    input.value = "";
    loadBlocked();
    loadStats();
  }
}

async function unblockIP(ip) {
  const res = await api(`/blocked/${encodeURIComponent(ip)}`, { method: "DELETE" });
  if (res) {
    showToast(`${ip} unblocked.`, "t-ok");
    loadBlocked();
    loadStats();
  }
}

// ── Run Analysis ───────────────────────────────────────────────────────────────
async function runAnalysis() {
  if (isAnalyzing) return;
  isAnalyzing = true;

  const btn = document.getElementById("btn-analyze");
  btn.disabled = true;
  btn.textContent = "Analyzing...";
  document.getElementById("overlay").style.display = "flex";

  const result = await api("/detect", { method: "POST" });

  document.getElementById("overlay").style.display = "none";
  btn.disabled = false;
  btn.textContent = "▶ Run Analysis";
  isAnalyzing = false;

  if (result) {
    showResultModal(result);
    await refreshAll();
  }
}

function showResultModal(r) {
  const body = document.getElementById("modal-body");
  body.innerHTML = `
    <div class="m-stats">
      <div class="m-stat">
        <span class="m-val">${r.total_logs_analyzed}</span>
        <div class="m-lbl">Logs Analyzed</div>
      </div>
      <div class="m-stat red">
        <span class="m-val">${r.anomalies_detected}</span>
        <div class="m-lbl">Anomalies</div>
      </div>
      <div class="m-stat orange">
        <span class="m-val">${r.blocked_ips_added}</span>
        <div class="m-lbl">IPs Blocked</div>
      </div>
    </div>
    ${r.details.length ? `
      <div class="m-threats">
        <h4>Detected Threats</h4>
        ${r.details.map(d => `
          <div class="threat-row ${d.severity}">
            <span class="t-ip">${esc(d.ip)}</span>
            <span class="t-sev sev-pill sev-${d.severity}">${d.severity}</span>
            <span class="t-rsn">${esc(d.reason)}</span>
          </div>
        `).join("")}
      </div>
    ` : `<p style="color:var(--green);text-align:center;padding:1rem;">✓ No threats found in current logs.</p>`}
  `;
  document.getElementById("modal").style.display = "flex";
}

function closeModal() {
  document.getElementById("modal").style.display = "none";
}

// ── File Upload ────────────────────────────────────────────────────────────────
async function uploadFile(input) {
  const file = input.files[0];
  if (!file) return;

  const statusEl = document.getElementById("upload-status");
  statusEl.textContent = `Uploading ${file.name}...`;
  statusEl.className = "upload-status";

  const formData = new FormData();
  formData.append("file", file);

  try {
    const res = await fetch(API + "/upload", {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}` },
      body: formData
    });

    const data = await res.json();
    if (res.ok && data.success) {
      statusEl.textContent = `✓ ${data.message}`;
      statusEl.className = "upload-status upload-ok";
      showToast(data.message, "t-ok");
      await refreshAll();
    } else {
      statusEl.textContent = `✗ ${data.detail || "Upload failed."}`;
      statusEl.className = "upload-status upload-err";
    }
  } catch (e) {
    statusEl.textContent = "✗ Upload error.";
    statusEl.className = "upload-status upload-err";
  }

  input.value = ""; // Reset input
}

// ── Charts ─────────────────────────────────────────────────────────────────────
function initCharts() {
  const chartDefaults = {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 500 },
    plugins: {
      legend: { labels: { color: "#6b7fa8", font: { family: "monospace", size: 11 } } },
      tooltip: {
        backgroundColor: "#0d1428", borderColor: "#1a2540", borderWidth: 1,
        titleColor: "#c8d6f0", bodyColor: "#6b7fa8"
      }
    }
  };

  // Bar chart
  const barCtx = document.getElementById("bar-chart").getContext("2d");
  barChart = new Chart(barCtx, {
    type: "bar",
    data: { labels: [], datasets: [{
      label: "Requests/min",
      data: [],
      backgroundColor: "rgba(0,255,136,0.2)",
      borderColor: "#00ff88",
      borderWidth: 1,
      borderRadius: 3,
    }]},
    options: {
      ...chartDefaults,
      scales: {
        x: { ticks: { color: "#3a4a68", font: { size: 9 }, maxTicksLimit: 8 }, grid: { color: "#0d1428" } },
        y: { ticks: { color: "#3a4a68", font: { size: 9 } }, grid: { color: "#0d1428" } }
      }
    }
  });

  // Pie chart
  const pieCtx = document.getElementById("pie-chart").getContext("2d");
  pieChart = new Chart(pieCtx, {
    type: "doughnut",
    data: {
      labels: ["Normal", "Suspicious"],
      datasets: [{
        data: [1, 0],
        backgroundColor: ["rgba(0,255,136,0.25)", "rgba(255,59,59,0.3)"],
        borderColor: ["#00ff88", "#ff3b3b"],
        borderWidth: 2,
      }]
    },
    options: {
      ...chartDefaults,
      cutout: "65%",
    }
  });
}

function updateBarChart(logs) {
  if (!barChart) return;
  // Aggregate requests per IP (top 10)
  const map = {};
  for (const l of logs) {
    map[l.ip] = (map[l.ip] || 0) + l.requests;
  }
  const sorted = Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, 10);
  barChart.data.labels = sorted.map(([ip]) => ip);
  barChart.data.datasets[0].data = sorted.map(([, v]) => v);
  barChart.update("none");
}

function updatePieChart(logs) {
  if (!pieChart) return;
  const suspicious = logs.filter(l => l.requests > 200 || l.login_attempts > 10).length;
  const normal = logs.length - suspicious;
  pieChart.data.datasets[0].data = [normal, suspicious];
  pieChart.update("none");
}

// ── Toast ──────────────────────────────────────────────────────────────────────
function showToast(msg, cls = "t-info") {
  const wrap = document.getElementById("toast-wrap");
  const t = document.createElement("div");
  t.className = `toast ${cls}`;
  t.innerHTML = `
    <div class="toast-hdr">
      <span>${cls === "t-threat" ? "⚠ ALERT" : cls === "t-ok" ? "✓ OK" : "ℹ INFO"}</span>
      <button onclick="this.closest('.toast').remove()">×</button>
    </div>
    <div class="toast-msg">${esc(msg)}</div>
  `;
  wrap.appendChild(t);
  setTimeout(() => t.classList.add("show"), 30);
  setTimeout(() => { t.classList.remove("show"); setTimeout(() => t.remove(), 350); }, 4500);
}

// ── Helpers ────────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function fmtTime(ts) {
  try {
    const d = new Date(ts.endsWith("Z") ? ts : ts + "Z");
    return d.toLocaleString([], { month:"short", day:"numeric", hour:"2-digit", minute:"2-digit", second:"2-digit" });
  } catch { return ts; }
}
