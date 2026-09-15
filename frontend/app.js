// app.js — SOC Copilot v2
// Talks to the FastAPI backend (http://localhost:8001) and renders the full dashboard.
// No framework — plain DOM updates stay readable at this scale.

const API_BASE = "https://soc-copilot-production.up.railway.app";

let alerts = [];
let incidents = [];
let selectedAlertId = null;
let selectedIncidentId = null;
let pollTimer = null;   // for triage-all progress polling

// ============================================================
// TAB NAVIGATION
// ============================================================

function switchTab(name) {
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.add("hidden"));
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  document.getElementById(`panel${capitalize(name)}`).classList.remove("hidden");
  document.getElementById(`tab${capitalize(name)}`).classList.add("active");

  // Lazy-load tab data on first switch
  if (name === "incidents") fetchIncidents();
  if (name === "audit") fetchAuditLog();
  if (name === "simulator") fetchSimulatorState();
}

function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

// ============================================================
// DATA FETCHING
// ============================================================

async function fetchAlerts() {
  const res = await fetch(`${API_BASE}/alerts`);
  alerts = await res.json();
  applyFilters();   // re-apply active filters whenever data is refreshed
}

async function fetchStats() {
  const res = await fetch(`${API_BASE}/stats`);
  const stats = await res.json();
  renderStats(stats);
}

async function fetchIncidents() {
  const res = await fetch(`${API_BASE}/incidents`);
  incidents = await res.json();
  renderIncidents();
}

async function fetchAuditLog() {
  const res = await fetch(`${API_BASE}/audit-logs`);
  const logs = await res.json();
  renderAuditLog(logs);
}

async function fetchSimulatorState() {
  const res = await fetch(`${API_BASE}/simulator-state`);
  const state = await res.json();
  renderSimulatorState(state);
}

async function fetchTriageStatus() {
  const res = await fetch(`${API_BASE}/alerts/triage-status`);
  return await res.json();
}

// ============================================================
// FILTER BAR
// ============================================================

function applyFilters() {
  const search = (document.getElementById("filterSearch").value || "").toLowerCase().trim();
  const severity = document.getElementById("filterSeverity").value;
  const status = document.getElementById("filterStatus").value;

  const hasFilter = search || severity || status;
  document.getElementById("clearFiltersBtn").style.display = hasFilter ? "inline-flex" : "none";

  const filtered = alerts.filter(a => {
    if (severity && a.llm_severity !== severity) return false;
    if (status && a.status !== status) return false;
    if (search) {
      const haystack = [
        a.alert_type,
        a.source_ip,
        a.dest_ip,
        a.mitre_technique,
        a.llm_severity,
        a.status,
      ].filter(Boolean).join(" ").toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });

  renderTable(filtered);

  const empty = document.getElementById("filterEmpty");
  empty.classList.toggle("hidden", filtered.length > 0);
}

function clearFilters() {
  document.getElementById("filterSearch").value = "";
  document.getElementById("filterSeverity").value = "";
  document.getElementById("filterStatus").value = "";
  applyFilters();
}

// ============================================================
// TRIAGE ACTIONS
// ============================================================

async function triageOne(alertId) {
  const btn = document.getElementById("triageOneBtn");
  if (btn) { btn.disabled = true; btn.textContent = "Running Pipeline…"; }

  const res = await fetch(`${API_BASE}/alerts/${alertId}/triage`, { method: "POST" });
  const updated = await res.json();
  alerts = alerts.map(a => (a.id === updated.id ? updated : a));
  applyFilters();
  renderDetail(updated);
  fetchStats();
  fetchIncidents();
}

async function triageAll() {
  const btn = document.getElementById("triageAllBtn");
  btn.disabled = true;
  btn.textContent = "Pipeline Running…";

  const res = await fetch(`${API_BASE}/alerts/triage-all`, { method: "POST" });
  const resp = await res.json();

  if (resp.status === "already_running") {
    showToast("A triage run is already in progress.", "info");
    btn.disabled = false;
    btn.innerHTML = '<i data-lucide="zap"></i> Run Pipeline on All';
    lucide.createIcons();
    return;
  }

  if (resp.status === "nothing_to_do") {
    showToast("All alerts are already triaged.", "success");
    btn.disabled = false;
    btn.innerHTML = '<i data-lucide="zap"></i> Run Pipeline on All';
    lucide.createIcons();
    return;
  }

  // Poll for progress
  showToast(`Pipeline started for ${resp.count} alert(s). Polling for progress…`, "info");
  startProgressPolling();
}

function startProgressPolling() {
  const wrap = document.getElementById("triageProgressWrap");
  wrap.classList.remove("hidden");

  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    const status = await fetchTriageStatus();
    const pct = status.total > 0 ? Math.round((status.triaged / status.total) * 100) : 0;

    document.getElementById("triageProgressBar").style.width = `${pct}%`;
    document.getElementById("triageProgressCounts").textContent =
      `${status.triaged} / ${status.total} triaged`;

    // Refresh alert table live during polling
    await fetchAlerts();
    fetchStats();

    if (!status.in_progress) {
      clearInterval(pollTimer);
      wrap.classList.add("hidden");
      const btn = document.getElementById("triageAllBtn");
      btn.disabled = false;
      btn.innerHTML = '<i data-lucide="zap"></i> Run Pipeline on All';
      lucide.createIcons();
      showToast("All alerts triaged! Refreshing incidents…", "success");
      fetchIncidents();
    }
  }, 2500);
}

async function approveResponse(incidentId) {
  const confirmed = confirm(
    `Approve and execute the simulated response playbook for Incident #${incidentId}?\n\n` +
    `This will run the playbook against the SIMULATED firewall only — no real infrastructure will be affected.`
  );
  if (!confirmed) return;

  const btn = document.getElementById(`approveBtn-${incidentId}`);
  if (btn) { btn.disabled = true; btn.textContent = "Executing…"; }

  const res = await fetch(`${API_BASE}/incidents/${incidentId}/approve-response`, { method: "POST" });
  const result = await res.json();

  if (!res.ok) {
    showToast(result.detail || "Approval failed", "error");
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i data-lucide="check-circle"></i> Approve & Execute Response';
      lucide.createIcons();
    }
    return;
  }

  showToast(`${result.actions_taken} action(s) executed. Check Audit Trail.`, "success");
  fetchIncidents();
  fetchAuditLog();
  // Re-render incident detail if selected
  const incident = incidents.find(i => i.id === incidentId);
  if (incident) renderIncidentDetail({ ...incident, response_status: "executed" });
}

// ============================================================
// ADD ALERT MODAL
// ============================================================

function openAddAlertModal() {
  document.getElementById("addAlertModal").classList.remove("hidden");
  document.getElementById("formAlertType").focus();
}

function closeAddAlertModal(e) {
  // If called from overlay click, only close if the overlay itself was clicked
  if (e && e.target !== document.getElementById("addAlertModal")) return;
  document.getElementById("addAlertModal").classList.add("hidden");
  document.getElementById("addAlertForm").reset();
}

async function submitAddAlert(e) {
  e.preventDefault();
  const btn = document.getElementById("addAlertSubmitBtn");
  btn.disabled = true;
  btn.textContent = "Adding…";

  const payload = {
    alert_type: document.getElementById("formAlertType").value.trim(),
    source_ip: document.getElementById("formSourceIp").value.trim() || null,
    dest_ip: document.getElementById("formDestIp").value.trim() || null,
    raw_log: document.getElementById("formRawLog").value.trim(),
  };

  try {
    const res = await fetch(`${API_BASE}/alerts`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await res.json();
      showToast(err.detail || "Failed to add alert", "error");
      return;
    }

    const newAlert = await res.json();
    alerts.unshift(newAlert);
    applyFilters();
    fetchStats();
    showToast(`Alert "${newAlert.alert_type}" added successfully.`, "success");
    document.getElementById("addAlertModal").classList.add("hidden");
    document.getElementById("addAlertForm").reset();

    // Auto-select the new alert so the analyst can immediately see it
    selectedAlertId = newAlert.id;
    applyFilters();
    renderDetail(newAlert);
  } catch (err) {
    showToast("Network error — could not add alert.", "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Add Alert";
  }
}

// Close modal on Escape key
document.addEventListener("keydown", e => {
  if (e.key === "Escape") {
    document.getElementById("addAlertModal").classList.add("hidden");
    document.getElementById("addAlertForm").reset();
  }
});

// ============================================================
// RENDERING — ALERTS
// ============================================================

function threatScoreBadge(score) {
  if (score === null || score === undefined) return `<span class="badge badge-pending">—</span>`;
  const val = Math.round(score);
  if (val >= 75) return `<span class="badge badge-critical">${val}</span>`;
  if (val >= 25) return `<span class="badge badge-high">${val}</span>`;
  if (val > 0) return `<span class="badge badge-medium">${val}</span>`;
  return `<span class="badge badge-low">Clean</span>`;
}

function severityBadge(severity) {
  if (!severity) return `<span class="badge badge-pending">—</span>`;
  return `<span class="badge badge-${severity.toLowerCase()}">${severity}</span>`;
}

function mitreBadge(technique) {
  if (!technique) return `<span class="badge badge-pending" style="font-size:0.65rem">—</span>`;
  // Extract just the technique ID for the compact table cell (e.g. "T1110")
  const id = technique.match(/^(T\d+)/)?.[1] ?? technique.split("–")[0].trim();
  return `<span class="badge badge-mitre" title="${technique}">${id}</span>`;
}

function statusDot(status) {
  return `<span class="status-dot status-${status}"></span>${status}`;
}

function renderTable(filteredAlerts) {
  // If called without argument, use the full set
  const source = filteredAlerts ?? alerts;
  const tbody = document.getElementById("alertTableBody");
  const newCount = alerts.filter(a => a.status === "new").length;
  const badge = document.getElementById("newAlertBadge");
  badge.textContent = newCount > 0 ? `${newCount} new` : "";

  tbody.innerHTML = source.map(a => `
    <tr data-id="${a.id}" class="${a.id === selectedAlertId ? "selected" : ""}">
      <td><span class="alert-type">${a.alert_type}</span></td>
      <td><code class="ip-code">${a.source_ip || "—"}</code></td>
      <td>${threatScoreBadge(a.threat_intel_score)}</td>
      <td>${severityBadge(a.rule_severity)}</td>
      <td>${severityBadge(a.llm_severity)}</td>
      <td>${mitreBadge(a.mitre_technique)}</td>
      <td class="status-cell">${statusDot(a.status)}</td>
    </tr>
  `).join("");

  tbody.querySelectorAll("tr").forEach(row => {
    row.addEventListener("click", () => {
      selectedAlertId = parseInt(row.dataset.id, 10);
      renderTable(source);
      renderDetail(alerts.find(a => a.id === selectedAlertId));
    });
  });
}

function renderDetail(alert) {
  const panel = document.getElementById("detailPanel");
  if (!alert) {
    panel.innerHTML = `<div class="detail-empty">Select an alert to view AI triage details</div>`;
    return;
  }

  const needsTriage = alert.status === "new";
  const playbook = alert.pipeline_playbook ? JSON.parse(alert.pipeline_playbook) : null;

  panel.innerHTML = `
    <div class="detail-title">${alert.alert_type}</div>
    <div class="detail-meta">
      <code>${alert.source_ip || "unknown"}</code>
      <span class="arrow">→</span>
      <code>${alert.dest_ip || "unknown"}</code>
      ${alert.incident_id ? `<span class="incident-chip"><i data-lucide="link"></i> Incident #${alert.incident_id}</span>` : ""}
      ${alert.mitre_technique ? `<span class="mitre-chip" title="MITRE ATT&CK">${alert.mitre_technique}</span>` : ""}
    </div>

    <!-- Pipeline step trace -->
    <div class="pipeline-trace">
      <div class="pipeline-step ${alert.threat_intel_score !== null || alert.threat_intel_summary ? 'done' : 'pending'}">
        <span class="step-label">① Enrich</span>
        <span class="step-value">${alert.threat_intel_summary || (alert.status === 'new' ? '—' : 'skipped')}</span>
      </div>
      <div class="pipeline-step ${alert.rule_severity ? 'done' : 'pending'}">
        <span class="step-label">② Rule</span>
        <span class="step-value">${alert.rule_severity || '—'}</span>
      </div>
      <div class="pipeline-step ${alert.llm_severity ? 'done' : 'pending'}">
        <span class="step-label">③ Triage</span>
        <span class="step-value">${alert.llm_severity || '—'}</span>
      </div>
      <div class="pipeline-step ${alert.incident_id ? 'done' : (alert.status === 'triaged' ? 'skipped' : 'pending')}">
        <span class="step-label">④ Correlate</span>
        <span class="step-value">${alert.incident_id ? `Incident #${alert.incident_id}` : (alert.status === 'triaged' ? 'standalone' : '—')}</span>
      </div>
      <div class="pipeline-step ${alert.pipeline_playbook_status ? 'done' : 'pending'}">
        <span class="step-label">⑤ Response</span>
        <span class="step-value">${alert.pipeline_playbook_status || '—'}</span>
      </div>
    </div>

    <div class="detail-block">
      <div class="detail-block-label">Raw Log</div>
      <div class="detail-log">${alert.raw_log}</div>
    </div>

    <div class="detail-compare">
      <div class="compare-col">
        <div class="compare-col-label">Rule-Based</div>
        ${severityBadge(alert.rule_severity)}
        ${alert.rule_is_false_positive ? '<div class="fp-flag"><i data-lucide="flag"></i> likely FP</div>' : ''}
      </div>
      <div class="compare-col">
        <div class="compare-col-label">AI Triage</div>
        ${severityBadge(alert.llm_severity)}
        ${alert.llm_is_false_positive ? '<div class="fp-flag"><i data-lucide="flag"></i> likely FP</div>' : ''}
      </div>
    </div>

    ${alert.mitre_technique ? `
      <div class="detail-block">
        <div class="detail-block-label">MITRE ATT&CK Technique</div>
        <div class="mitre-full-badge">${alert.mitre_technique}</div>
      </div>
    ` : ""}

    ${alert.llm_reasoning ? `
      <div class="detail-block">
        <div class="detail-block-label">AI Reasoning</div>
        <div>${alert.llm_reasoning}</div>
      </div>
    ` : ""}

    ${alert.llm_recommended_action ? `
      <div class="detail-block">
        <div class="detail-block-label">Recommended Action</div>
        <div>${alert.llm_recommended_action}</div>
      </div>
    ` : ""}

    ${playbook ? `
      <div class="detail-block">
        <div class="detail-block-label">Response Playbook
          <span class="playbook-status status-${alert.pipeline_playbook_status}">${alert.pipeline_playbook_status}</span>
        </div>
        <div class="playbook-steps">
          ${playbook.steps.map((s, i) => `
            <div class="playbook-step">
              <span class="step-num">${i + 1}</span>
              <span class="action-chip action-${s.action}">${s.action.replace(/_/g, ' ')}</span>
              <span class="step-desc">${s.description}</span>
            </div>
          `).join("")}
        </div>
      </div>
    ` : ""}

    ${needsTriage ? `<button class="btn btn-triage" id="triageOneBtn"><i data-lucide="play"></i> Run AI Pipeline</button>` : ""}
  `;

  const triageBtn = document.getElementById("triageOneBtn");
  if (triageBtn) triageBtn.addEventListener("click", () => triageOne(alert.id));

  lucide.createIcons();
}

// ============================================================
// RENDERING — INCIDENTS
// ============================================================

function renderIncidents() {
  const container = document.getElementById("incidentCards");
  if (!incidents.length) {
    container.innerHTML = `<div class="empty-state">No incidents yet — run triage to auto-correlate alerts.</div>`;
    return;
  }

  container.innerHTML = incidents.map(inc => `
    <div class="incident-card ${inc.id === selectedIncidentId ? 'selected' : ''}" data-id="${inc.id}">
      <div class="incident-card-header">
        <span class="incident-id">#${inc.id}</span>
        ${severityBadge(inc.severity)}
        <span class="response-status-chip status-${inc.response_status || 'none'}">${inc.response_status || 'no response'}</span>
      </div>
      <div class="incident-card-title">${inc.title}</div>
      <div class="incident-card-meta">${inc.alerts.length} alert(s) · ${formatDate(inc.created_at)}</div>
    </div>
  `).join("");

  container.querySelectorAll(".incident-card").forEach(card => {
    card.addEventListener("click", () => {
      selectedIncidentId = parseInt(card.dataset.id, 10);
      renderIncidents();
      renderIncidentDetail(incidents.find(i => i.id === selectedIncidentId));
    });
  });
}

function renderIncidentDetail(incident) {
  const panel = document.getElementById("incidentDetailPanel");
  if (!incident) {
    panel.innerHTML = `<div class="detail-empty">Select an incident</div>`;
    return;
  }

  const playbook = incident.playbook ? JSON.parse(incident.playbook) : null;
  const canApprove = incident.response_status === "proposed";

  panel.innerHTML = `
    <div class="detail-title">${incident.title}</div>
    <div class="detail-meta">
      ${severityBadge(incident.severity)}
      <span class="response-status-chip status-${incident.response_status || 'none'}">${incident.response_status || 'no response'}</span>
      <span style="color:var(--text-muted);font-size:0.8rem">${formatDate(incident.created_at)}</span>
    </div>

    ${incident.summary ? `
      <div class="detail-block">
        <div class="detail-block-label">AI Incident Summary</div>
        <div class="incident-summary">${incident.summary}</div>
      </div>
    ` : ""}

    <div class="detail-block">
      <div class="detail-block-label">Correlated Alerts (${incident.alerts.length})</div>
      <div class="correlated-alerts">
        ${incident.alerts.map(a => `
          <div class="correlated-alert-row">
            <span class="badge badge-${(a.llm_severity || 'pending').toLowerCase()}">${a.llm_severity || '?'}</span>
            <span class="alert-type">${a.alert_type}</span>
            <code class="ip-code">${a.source_ip || '—'}</code>
            ${a.mitre_technique ? `<span class="badge badge-mitre" style="font-size:0.65rem" title="${a.mitre_technique}">${a.mitre_technique.match(/^(T\d+)/)?.[1] ?? ''}</span>` : ''}
          </div>
        `).join("")}
      </div>
    </div>

    ${playbook ? `
      <div class="detail-block">
        <div class="detail-block-label">Response Playbook</div>
        <div class="playbook-steps">
          ${playbook.steps.map((s, i) => `
            <div class="playbook-step">
              <span class="step-num">${i + 1}</span>
              <span class="action-chip action-${s.action}">${s.action.replace(/_/g, ' ')}</span>
              <span class="step-desc">${s.description}</span>
            </div>
          `).join("")}
        </div>
      </div>
    ` : `<div class="detail-block"><div class="detail-block-label">Playbook</div><div style="color:var(--text-muted)">No playbook yet — triage linked alerts first.</div></div>`}

    ${canApprove ? `
      <button class="btn btn-approve" id="approveBtn-${incident.id}"><i data-lucide="check-circle"></i> Approve & Execute Response</button>
      <div class="approve-note">This executes against the <strong>simulated firewall only</strong>. No real infrastructure is affected.</div>
    ` : incident.response_status === "executed" ? `
      <div class="executed-note"><i data-lucide="check"></i> Response has been executed. See Audit Trail for details.</div>
    ` : ""}
  `;

  if (canApprove) {
    document.getElementById(`approveBtn-${incident.id}`)
      .addEventListener("click", () => approveResponse(incident.id));
  }

  lucide.createIcons();
}

// ============================================================
// RENDERING — AUDIT LOG
// ============================================================

function renderAuditLog(logs) {
  const tbody = document.getElementById("auditTableBody");
  if (!logs.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No audit log entries yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = logs.map(l => `
    <tr>
      <td class="audit-time">${formatDate(l.timestamp)}</td>
      <td>${l.incident_id ? `#${l.incident_id}` : l.alert_id ? `A#${l.alert_id}` : "—"}</td>
      <td><span class="action-chip action-${l.action}">${l.action.replace(/_/g, ' ')}</span></td>
      <td class="audit-desc">${l.description || "—"}</td>
      <td><span class="actor-chip actor-${l.actor}">${l.actor}</span></td>
      <td><span class="outcome-chip outcome-${l.outcome}">${l.outcome}</span></td>
    </tr>
  `).join("");
}

// ============================================================
// RENDERING — SIMULATOR STATE
// ============================================================

function renderSimulatorState(state) {
  const el = document.getElementById("simulatorState");

  const section = (title, items, emptyMsg, renderFn) => `
    <div class="sim-section">
      <div class="sim-section-title">${title}</div>
      ${items.length ? items.map(renderFn).join("") : `<div class="sim-empty">${emptyMsg}</div>`}
    </div>
  `;

  el.innerHTML = `
    ${section('<i data-lucide="ban"></i> Blocked IPs', state.blocked_ips, "None blocked yet",
    ip => `<div class="sim-item"><code>${ip}</code></div>`)}

    ${section('<i data-lucide="lock"></i> Isolated Hosts', state.isolated_hosts, "None isolated yet",
      h => `<div class="sim-item"><code>${h}</code></div>`)}

    ${section('<i data-lucide="flask-conical"></i> Forensics Jobs', state.forensics_jobs, "None started",
        j => `<div class="sim-item"><code>${j.host}</code> <span class="sim-meta">${j.started_at}</span></div>`)}

    ${section('<i data-lucide="bell"></i> Analyst Notifications', state.analyst_notifications, "None sent",
          n => `<div class="sim-item">${n.message} <span class="sim-meta">${n.sent_at}</span></div>`)}

    <div class="sim-section">
      <div class="sim-section-title"><i data-lucide="clipboard-list"></i> Action Log (last 50)</div>
      ${state.action_log.length
      ? `<div class="action-log">${state.action_log.slice().reverse().map(l =>
        `<div class="action-log-entry">${l}</div>`).join("")}</div>`
      : `<div class="sim-empty">No actions yet</div>`}
    </div>
  `;

  lucide.createIcons();
}

// ============================================================
// RENDERING — STATS
// ============================================================

function renderStats(stats) {
  document.getElementById("statTotal").textContent = stats.total_alerts;
  document.getElementById("statTriaged").textContent = stats.triaged_alerts;
  document.getElementById("statIncidents").textContent = stats.total_incidents ?? "—";
  document.getElementById("statAgreement").textContent =
    stats.rule_llm_agreement_rate !== null
      ? `${Math.round(stats.rule_llm_agreement_rate * 100)}%`
      : "—";

  const sevColors = {
    Low: "var(--sev-low)",
    Medium: "var(--sev-medium)",
    High: "var(--sev-high)",
    Critical: "var(--sev-critical)",
  };
  const maxCount = Math.max(1, ...Object.values(stats.severity_breakdown_llm));

  document.getElementById("severityBars").innerHTML = Object.entries(
    stats.severity_breakdown_llm
  ).map(([sev, count]) => `
    <div class="severity-bar-row">
      <span class="bar-label">${sev}</span>
      <div class="severity-bar-track">
        <div class="severity-bar-fill" style="width:${(count / maxCount) * 100}%;background:${sevColors[sev]}"></div>
      </div>
      <span>${count}</span>
    </div>
  `).join("");
}

// ============================================================
// UTILITIES
// ============================================================

function formatDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

let toastTimer = null;
function showToast(msg, type = "info") {
  let toast = document.getElementById("toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "toast";
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.className = `toast toast-${type} show`;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 4000);
}

// ============================================================
// INIT
// ============================================================

document.getElementById("triageAllBtn").addEventListener("click", triageAll);

fetchAlerts();
fetchStats();
lucide.createIcons();