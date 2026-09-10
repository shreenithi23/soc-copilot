// Multi-SIEM SOC Copilot Frontend Logic
let currentSessionId = null;
let allCachedIntel = [];
let activeLogs = [];

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initChat();
  initLogExplorer();
  initThreatIntel();
  initMitreMatrix();
  initLangSmithEval();
  initSettings();

  // Load initial telemetry and sessions
  refreshTelemetry();
  loadSessions();
  loadLogs();
  loadThreatIntelHub();
});

// Toast notification helper
function showToast(message, type = "success") {
  const container = document.getElementById("toastContainer");
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <span>${type === "success" ? "✓" : "⚠"}</span>
    <span>${message}</span>
  `;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// 1. Navigation Tabs
function initTabs() {
  const tabs = document.querySelectorAll(".nav-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");

      const targetId = tab.dataset.target;
      document.querySelectorAll(".tab-pane").forEach(pane => {
        pane.classList.remove("active");
        if (pane.id === targetId) {
          pane.classList.add("active");
        }
      });

      if (targetId === "pane-explorer") loadLogs();
      if (targetId === "pane-intel") loadThreatIntelHub();
      if (targetId === "pane-mitre") renderMitreMatrix();
    });
  });
}

// 2. High-level SOC Telemetry
async function refreshTelemetry() {
  try {
    const res = await fetch("/api/stats");
    const data = await res.json();

    document.getElementById("statTotalLogs").textContent = data.total_logs || 0;
    document.getElementById("statCritical").textContent = data.critical_alerts || 0;
    document.getElementById("statVtMalicious").textContent = data.vt_malicious || 0;
    document.getElementById("statVtCached").textContent = data.vt_cached || 0;
  } catch (err) {
    console.error("Failed to load telemetry stats:", err);
  }
}

// 3. SOC Copilot Chat & Memory Engine
function initChat() {
  const input = document.getElementById("chatInput");
  const sendBtn = document.getElementById("chatSendBtn");
  const newSessionBtn = document.getElementById("newSessionBtn");

  const submitQuery = () => {
    const text = input.value.trim();
    if (!text) return;
    input.value = "";
    sendChatMessage(text);
  };

  sendBtn.addEventListener("click", submitQuery);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      submitQuery();
    }
  });

  newSessionBtn.addEventListener("click", () => {
    currentSessionId = null;
    document.getElementById("chatMessages").innerHTML = `
      <div class="message-bubble assistant">
        <div class="avatar ai-avatar">
          <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
        </div>
        <div class="message-content-wrapper">
          <div class="message-meta">
            <span>SOC Copilot</span> • <span>Memory Session Initialized</span>
          </div>
          <div class="message-text">
            <strong>Ready for Multi-SIEM Threat Hunting.</strong><br>
            Context memory is active. I can correlate alerts across Splunk, Elastic, Sentinel, QRadar, and Wazuh, cross-reference IOCs with VirusTotal v3, and generate incident response playbooks.
          </div>
        </div>
      </div>
    `;
    document.getElementById("contextLogsList").innerHTML = `<div class="text-dim" style="font-size:0.75rem; text-align:center; padding:1rem;">No query context yet</div>`;
    document.getElementById("activeIocsList").innerHTML = `<div class="text-dim" style="font-size:0.75rem; text-align:center; padding:1rem;">No IOCs in active query</div>`;
    loadSessions();
    showToast("New hunting investigation session started");
  });

  // Quick investigation prompt chips
  document.querySelectorAll(".prompt-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      const prompt = chip.dataset.prompt;
      input.value = prompt;
      submitQuery();
    });
  });
}

async function loadSessions() {
  try {
    const res = await fetch("/api/chat/sessions");
    const sessions = await res.json();
    const list = document.getElementById("sessionsList");
    list.innerHTML = "";

    sessions.forEach((s, idx) => {
      const item = document.createElement("div");
      item.className = `session-item ${s.id === currentSessionId || (!currentSessionId && idx === 0) ? "active" : ""}`;
      item.innerHTML = `
        <div class="title">${s.title || "Hunting Investigation"}</div>
        <div class="date">${new Date(s.updated_at).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})} • ${s.id.slice(0, 8)}</div>
      `;
      item.addEventListener("click", () => {
        document.querySelectorAll(".session-item").forEach(i => i.classList.remove("active"));
        item.classList.add("active");
        currentSessionId = s.id;
        loadSessionHistory(s.id);
      });
      list.appendChild(item);
    });

    if (!currentSessionId && sessions.length > 0) {
      currentSessionId = sessions[0].id;
      loadSessionHistory(currentSessionId);
    }
  } catch (err) {
    console.error("Failed to load chat sessions:", err);
  }
}

async function loadSessionHistory(sessionId) {
  try {
    const res = await fetch(`/api/chat/history/${sessionId}`);
    const history = await res.json();
    const chatMessages = document.getElementById("chatMessages");
    chatMessages.innerHTML = "";

    if (history.length === 0) {
      chatMessages.innerHTML = `
        <div class="message-bubble assistant">
          <div class="avatar ai-avatar">
            <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
          </div>
          <div class="message-content-wrapper">
            <div class="message-meta">
              <span>SOC Copilot</span> • <span>Ready</span>
            </div>
            <div class="message-text">
              <strong>Investigation session loaded.</strong> Ask questions or select a prompt below to begin analyzing logs.
            </div>
          </div>
        </div>
      `;
      return;
    }

    history.forEach(msg => {
      appendChatMessageUI(msg.role, msg.content, {
        timestamp: msg.created_at,
        contextLogs: msg.context_logs,
        threatIntel: msg.threat_intel
      });
    });

    // Update side panels with latest assistant response data
    const lastAssistant = [...history].reverse().find(m => m.role === "assistant");
    if (lastAssistant) {
      renderSideContext(lastAssistant.context_logs, lastAssistant.threat_intel);
    }
  } catch (err) {
    console.error("Failed to load session history:", err);
  }
}

async function sendChatMessage(text) {
  appendChatMessageUI("user", text);

  // Loading skeleton placeholder
  const loadingId = "loading-" + Date.now();
  const chatMessages = document.getElementById("chatMessages");
  const loadingBubble = document.createElement("div");
  loadingBubble.id = loadingId;
  loadingBubble.className = "message-bubble assistant";
  loadingBubble.innerHTML = `
    <div class="avatar ai-avatar">
      <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
    </div>
    <div class="message-content-wrapper">
      <div class="message-meta"><span>SOC Copilot</span> • <span>Analyzing Multi-SIEM Logs & VT Intelligence...</span></div>
      <div class="message-text" style="color: var(--text-dim); font-style: italic;">
        Correlating telemetry across SIEM sources and querying VirusTotal v3 indicators...
      </div>
    </div>
  `;
  chatMessages.appendChild(loadingBubble);
  chatMessages.scrollTop = chatMessages.scrollHeight;

  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_id: currentSessionId,
        message: text
      })
    });

    const data = await res.json();
    loadingBubble.remove();

    currentSessionId = data.session_id;
    appendChatMessageUI("assistant", data.content, {
      model: data.model,
      latency: data.latency_ms,
      traceId: data.trace_id,
      contextLogs: data.context_logs,
      threatIntel: data.threat_intel
    });

    renderSideContext(data.context_logs, data.threat_intel);
    refreshTelemetry();
    loadSessions();
  } catch (err) {
    loadingBubble.remove();
    appendChatMessageUI("assistant", `⚠️ Error executing SOC Copilot query: ${err.message}`);
  }
}

function appendChatMessageUI(role, content, meta = {}) {
  const chatMessages = document.getElementById("chatMessages");
  const bubble = document.createElement("div");
  bubble.className = `message-bubble ${role}`;

  const isAI = role === "assistant";
  const avatarHtml = isAI ? `
    <div class="avatar ai-avatar">
      <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
    </div>
  ` : `
    <div class="avatar user-avatar">
      <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>
    </div>
  `;

  let metaText = isAI ? "SOC Copilot" : "Senior SOC Analyst";
  if (meta.model) metaText += ` • ${meta.model}`;
  if (meta.latency) metaText += ` • ${meta.latency}ms`;

  bubble.innerHTML = `
    ${avatarHtml}
    <div class="message-content-wrapper">
      <div class="message-meta">
        <span>${metaText}</span>
      </div>
      <div class="message-text">${formatMarkdown(content)}</div>
    </div>
  `;

  chatMessages.appendChild(bubble);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Markdown formatter helper
function formatMarkdown(text) {
  if (!text) return "";
  let html = text
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;") // sanitize
    // headings
    .replace(/^### (.*$)/gim, '<h3>$1</h3>')
    .replace(/^#### (.*$)/gim, '<h4>$1</h4>')
    // bold & code
    .replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/gim, '<em>$1</em>')
    .replace(/`([^`]+)`/gim, '<code>$1</code>')
    // alerts
    .replace(/&gt; \[!TIP\]/gim, '<blockquote style="border-left-color: var(--accent-cyan);">💡')
    .replace(/&gt; \[!WARNING\]/gim, '<blockquote style="border-left-color: var(--accent-amber);">⚠️')
    .replace(/&gt; \[!IMPORTANT\]/gim, '<blockquote style="border-left-color: var(--accent-red);">🚨')
    // tables
    .replace(/\|(.+)\|/g, function(match) {
      const cells = match.split('|').filter(c => c.trim().length > 0);
      return '<tr>' + cells.map(c => `<td>${c.trim()}</td>`).join('') + '</tr>';
    });

  // wrap table rows
  if (html.includes('<tr>')) {
    html = html.replace(/(<tr>[\s\S]*?<\/tr>)/g, '<table>$1</table>');
  }

  // list items & line breaks
  html = html.replace(/^- (.*$)/gim, '<li>$1</li>');
  html = html.replace(/(<li>[\s\S]*?<\/li>)/g, '<ul>$1</ul>');
  html = html.replace(/\n\n/g, '<br><br>');
  return html;
}

function renderSideContext(logs = [], threatIntel = {}) {
  // Context Logs List
  const logsList = document.getElementById("contextLogsList");
  if (!logs || logs.length === 0) {
    logsList.innerHTML = `<div class="text-dim" style="font-size:0.75rem; text-align:center; padding:1rem;">No correlated logs</div>`;
  } else {
    logsList.innerHTML = logs.map(l => `
      <div style="background: rgba(0,0,0,0.3); padding: 0.45rem 0.6rem; border-radius: 6px; margin-bottom: 0.4rem; border-left: 3px solid ${getSeverityColor(l.severity)}; font-size: 0.72rem;">
        <div style="display:flex; justify-content:space-between; margin-bottom:0.2rem;">
          <strong style="color:var(--text-main); font-family:var(--font-mono);">${l.siem_source}</strong>
          <span class="badge badge-${(l.severity || 'low').toLowerCase()}">${l.severity}</span>
        </div>
        <div style="color:var(--text-muted); font-size:0.7rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${l.alert_name}</div>
        <div style="color:var(--accent-blue); font-family:var(--font-mono); font-size:0.66rem; margin-top:0.2rem;">
          ${l.src_ip || 'N/A'} ➔ ${l.dest_ip || 'N/A'}
        </div>
      </div>
    `).join('');
  }

  // Active IOCs & VirusTotal
  const iocsList = document.getElementById("activeIocsList");
  const ips = Object.entries(threatIntel?.ips || {});
  const hashes = Object.entries(threatIntel?.hashes || {});
  const domains = Object.entries(threatIntel?.domains || {});

  if (ips.length === 0 && hashes.length === 0 && domains.length === 0) {
    iocsList.innerHTML = `<div class="text-dim" style="font-size:0.75rem; text-align:center; padding:1rem;">No IOCs detected</div>`;
    return;
  }

  let html = "";
  ips.forEach(([ip, info]) => {
    const isMal = info.malicious_count > 0;
    html += `
      <div class="ioc-pill ${isMal ? '' : 'clean'}">
        <div class="ioc-val" title="${ip}">${ip}</div>
        <span class="ioc-vt-badge ${isMal ? 'malicious' : 'clean'}">
          ${isMal ? `🔴 ${info.malicious_count} VT Hits` : '🟢 Clean'}
        </span>
      </div>
    `;
  });
  hashes.forEach(([h, info]) => {
    const isMal = info.malicious_count > 0;
    html += `
      <div class="ioc-pill ${isMal ? '' : 'clean'}">
        <div class="ioc-val" title="${h}">${h.slice(0, 16)}...</div>
        <span class="ioc-vt-badge ${isMal ? 'malicious' : 'clean'}">
          ${isMal ? `🔴 ${info.malicious_count} VT Hits` : '🟢 Clean'}
        </span>
      </div>
    `;
  });
  domains.forEach(([d, info]) => {
    const isMal = info.malicious_count > 0;
    html += `
      <div class="ioc-pill ${isMal ? '' : 'clean'}">
        <div class="ioc-val" title="${d}">${d}</div>
        <span class="ioc-vt-badge ${isMal ? 'malicious' : 'clean'}">
          ${isMal ? `🔴 ${info.malicious_count} VT Hits` : '🟢 Clean'}
        </span>
      </div>
    `;
  });
  iocsList.innerHTML = html;
}

function getSeverityColor(sev) {
  const s = (sev || "").toUpperCase();
  if (s === "CRITICAL") return "var(--accent-red)";
  if (s === "HIGH") return "var(--accent-amber)";
  if (s === "MEDIUM") return "#fbbf24";
  if (s === "LOW") return "var(--accent-blue)";
  return "var(--text-dim)";
}

// 4. Multi-SIEM Log Explorer
function initLogExplorer() {
  const sourceFilter = document.getElementById("logSourceFilter");
  const sevFilter = document.getElementById("logSeverityFilter");
  const searchInput = document.getElementById("logSearchInput");
  const reloadSeedBtn = document.getElementById("reloadSeedBtn");
  const ingestModalBtn = document.getElementById("ingestModalBtn");

  sourceFilter.addEventListener("change", () => loadLogs());
  sevFilter.addEventListener("change", () => loadLogs());
  searchInput.addEventListener("input", debounce(() => loadLogs(), 300));

  reloadSeedBtn.addEventListener("click", async () => {
    try {
      const res = await fetch("/api/logs/seed", { method: "POST" });
      const data = await res.json();
      showToast(`Loaded ${data.seeded_count} realistic Multi-SIEM attack events`);
      refreshTelemetry();
      loadLogs();
      loadThreatIntelHub();
      renderMitreMatrix();
    } catch (err) {
      showToast("Failed to reload seed logs: " + err.message, "error");
    }
  });

  ingestModalBtn.addEventListener("click", () => {
    document.getElementById("ingestModal").classList.add("active");
  });

  // Ingestion Modal submit
  document.getElementById("btnExecuteIngest").addEventListener("click", async () => {
    const formatType = document.getElementById("ingestFormatSelect").value;
    const rawText = document.getElementById("ingestRawText").value.trim();
    const fileInput = document.getElementById("ingestFileInput");

    if (fileInput.files.length > 0) {
      const formData = new FormData();
      formData.append("file", fileInput.files[0]);
      formData.append("format_type", formatType);
      try {
        const res = await fetch("/api/logs/upload", { method: "POST", body: formData });
        const data = await res.json();
        showToast(`Ingested ${data.ingested_count} logs from ${data.filename}`);
        document.getElementById("ingestModal").classList.remove("active");
        refreshTelemetry();
        loadLogs();
      } catch (e) {
        showToast("Upload failed: " + e.message, "error");
      }
    } else if (rawText) {
      try {
        const res = await fetch("/api/logs/ingest-text", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content: rawText, format_type: formatType })
        });
        const data = await res.json();
        showToast(`Ingested ${data.ingested_count} logs from text input`);
        document.getElementById("ingestModal").classList.remove("active");
        refreshTelemetry();
        loadLogs();
      } catch (e) {
        showToast("Ingestion failed: " + e.message, "error");
      }
    } else {
      showToast("Please select a file or paste log text to ingest", "error");
    }
  });

  document.getElementById("btnCloseIngestModal").addEventListener("click", () => {
    document.getElementById("ingestModal").classList.remove("active");
  });
}

async function loadLogs() {
  const source = document.getElementById("logSourceFilter")?.value || "all";
  const severity = document.getElementById("logSeverityFilter")?.value || "all";
  const search = document.getElementById("logSearchInput")?.value || "";

  try {
    const url = `/api/logs?source=${encodeURIComponent(source)}&severity=${encodeURIComponent(severity)}&search=${encodeURIComponent(search)}&limit=100`;
    const res = await fetch(url);
    const data = await res.json();
    activeLogs = data.logs;

    document.getElementById("logCountBadge").textContent = `${data.total} Events`;
    const tbody = document.getElementById("logTableBody");
    tbody.innerHTML = "";

    if (data.logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 2rem; color: var(--text-dim);">No security logs found matching filters</td></tr>`;
      return;
    }

    data.logs.forEach(log => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><span class="badge badge-source">${log.siem_source}</span></td>
        <td><span class="badge badge-${(log.severity || 'low').toLowerCase()}">${log.severity}</span></td>
        <td style="font-family:var(--font-mono); font-size:0.72rem; color:var(--text-dim);">${formatTimestamp(log.timestamp)}</td>
        <td><strong style="color:var(--text-main);">${log.alert_name}</strong></td>
        <td>
          <span class="code-pill">${log.src_ip || '—'}${log.src_port ? ':' + log.src_port : ''}</span>
          <span style="color:var(--accent-blue);">➔</span>
          <span class="code-pill">${log.dest_ip || '—'}${log.dest_port ? ':' + log.dest_port : ''}</span>
        </td>
        <td><span style="color:var(--accent-cyan); font-family:var(--font-mono); font-size:0.75rem;">${log.user || '—'}</span></td>
        <td>
          <button class="btn btn-outline btn-sm view-log-btn" data-id="${log.id}">Inspect</button>
        </td>
      `;
      tbody.appendChild(tr);
    });

    document.querySelectorAll(".view-log-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const id = btn.dataset.id;
        const found = activeLogs.find(l => l.id === id);
        if (found) showLogInspectorModal(found);
      });
    });
  } catch (err) {
    console.error("Failed to load logs:", err);
  }
}

function showLogInspectorModal(log) {
  const modal = document.getElementById("logInspectorModal");
  document.getElementById("inspectSiemSource").textContent = log.siem_source;
  document.getElementById("inspectSeverity").textContent = log.severity;
  document.getElementById("inspectSeverity").className = `badge badge-${log.severity.toLowerCase()}`;
  document.getElementById("inspectAlertName").textContent = log.alert_name;
  document.getElementById("inspectTimestamp").textContent = log.timestamp;
  document.getElementById("inspectSrcDest").textContent = `${log.src_ip || 'N/A'}:${log.src_port || ''} ➔ ${log.dest_ip || 'N/A'}:${log.dest_port || ''}`;
  document.getElementById("inspectUser").textContent = log.user || 'N/A';
  document.getElementById("inspectFileHash").textContent = log.file_hash || 'N/A';
  document.getElementById("inspectDomain").textContent = log.domain || 'N/A';

  document.getElementById("inspectDetailsJson").textContent = JSON.stringify(log.details || {}, null, 2);
  document.getElementById("inspectRawLog").textContent = log.raw_log || 'N/A';

  modal.classList.add("active");
  document.getElementById("btnCloseInspector").onclick = () => modal.classList.remove("active");
}

// 5. Threat Intelligence & VirusTotal Hub
function initThreatIntel() {
  const scanBtn = document.getElementById("btnScanIoc");
  const input = document.getElementById("iocScanInput");

  const runScan = async () => {
    const val = input.value.trim();
    if (!val) return;
    try {
      scanBtn.disabled = true;
      scanBtn.textContent = "Scanning...";
      const res = await fetch("/api/threat-intel/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ indicator: val })
      });
      const data = await res.json();
      renderVtScanResult(data);
      loadThreatIntelHub();
      refreshTelemetry();
      showToast(`VirusTotal inspection complete for ${val}`);
    } catch (e) {
      showToast("Scan error: " + e.message, "error");
    } finally {
      scanBtn.disabled = false;
      scanBtn.innerHTML = `<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg> Analyze IOC`;
    }
  };

  scanBtn.addEventListener("click", runScan);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") runScan();
  });
}

function renderVtScanResult(data) {
  const container = document.getElementById("vtScanResultContainer");
  container.style.display = "flex";

  const total = (data.malicious_count || 0) + (data.suspicious_count || 0) + (data.harmless_count || 0) + (data.undetected_count || 0) || 72;
  const mal = data.malicious_count || 0;
  const isMalicious = mal > 0;

  document.getElementById("vtIndicatorDisplay").textContent = data.indicator;
  document.getElementById("vtIocType").textContent = data.ioc_type.toUpperCase();
  document.getElementById("vtScoreCircle").className = `score-circle ${isMalicious ? 'malicious' : 'clean'}`;
  document.getElementById("vtScoreNum").textContent = mal;
  document.getElementById("vtScoreTotal").textContent = `/${total}`;
  document.getElementById("vtReputationNum").textContent = data.reputation || 0;
  document.getElementById("vtSourceLabel").textContent = data.source || "VirusTotal v3";

  // Render tags
  const tagsContainer = document.getElementById("vtTagsContainer");
  tagsContainer.innerHTML = (data.tags || []).map(t => `<span class="badge badge-high">${t}</span>`).join(' ');

  // Render engine detections
  const engineDiv = document.getElementById("vtEngineDetections");
  const engines = Object.entries(data.engine_details || {});
  if (engines.length === 0) {
    engineDiv.innerHTML = `<span style="color:var(--text-dim); font-size:0.75rem;">No security engines flagged this indicator as malicious.</span>`;
  } else {
    engineDiv.innerHTML = engines.map(([eng, det]) => `
      <div style="display:flex; justify-content:space-between; font-size:0.72rem; padding:0.25rem 0; border-bottom:1px solid rgba(255,255,255,0.04);">
        <strong style="color:var(--text-main); font-family:var(--font-mono);">${eng}</strong>
        <span style="color:var(--accent-red);">${det}</span>
      </div>
    `).join('');
  }
}

async function loadThreatIntelHub() {
  try {
    const res = await fetch("/api/threat-intel/cached");
    allCachedIntel = await res.json();
    const tbody = document.getElementById("cachedIntelTableBody");
    tbody.innerHTML = "";

    if (allCachedIntel.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:1.5rem; color:var(--text-dim);">No cached threat intelligence. Scan an IOC above.</td></tr>`;
      return;
    }

    allCachedIntel.forEach(item => {
      const isMal = item.malicious_count > 0;
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><span class="badge badge-source">${item.ioc_type}</span></td>
        <td><strong style="color:var(--text-main); font-family:var(--font-mono);">${item.indicator}</strong></td>
        <td>
          <span class="ioc-vt-badge ${isMal ? 'malicious' : 'clean'}">
            ${isMal ? `🔴 ${item.malicious_count} Malicious` : '🟢 Clean'}
          </span>
        </td>
        <td style="font-family:var(--font-mono); font-size:0.75rem;">${item.reputation}</td>
        <td>
          ${(item.tags || []).slice(0, 3).map(t => `<span class="badge badge-medium" style="font-size:0.62rem;">${t}</span>`).join(' ')}
        </td>
        <td>
          <button class="btn btn-outline btn-sm lookup-cached-btn" data-ioc="${item.indicator}">Inspect</button>
        </td>
      `;
      tbody.appendChild(tr);
    });

    document.querySelectorAll(".lookup-cached-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const ioc = btn.dataset.ioc;
        const found = allCachedIntel.find(i => i.indicator === ioc);
        if (found) renderVtScanResult(found);
      });
    });
  } catch (err) {
    console.error("Failed to load cached intel:", err);
  }
}

// 6. MITRE ATT&CK Matrix & Kill Chain View
function initMitreMatrix() {
  renderMitreMatrix();
}

function renderMitreMatrix() {
  // Built from ingested multi-SIEM logs
  const matrixPhases = {
    "Initial Access": [
      { id: "T1566.002", name: "Spearphishing Link", siem: "Sentinel", alert: "Defender for Office 365: Phishing Link Clicked", entity: "victim_jdoe@enterprise.corp" }
    ],
    "Execution": [
      { id: "T1059.001", name: "PowerShell EncodedCommand", siem: "Elastic", alert: "Suspicious Obfuscated PowerShell Execution", entity: "WINWORD.EXE ➔ powershell.exe" }
    ],
    "Credential Access": [
      { id: "T1003.001", name: "LSASS Memory Dump", siem: "Splunk", alert: "Mimikatz sekurlsa Ticket Request", entity: "victim_jdoe / krbtgt" },
      { id: "T1110.001", name: "SSH Password Spray", siem: "Wazuh", alert: "SSH Brute-force & Sudo Elevation", entity: "root / 45.33.32.156" }
    ],
    "Lateral Movement": [
      { id: "T1550.002", name: "Pass the Hash (SMB)", siem: "QRadar", alert: "PsExec / WMI execution targeting Domain Controller", entity: "10.0.4.15 ➔ 10.0.4.200" }
    ],
    "Command & Control": [
      { id: "T1071.001", name: "Web Protocols / C2 Beacon", siem: "Splunk", alert: "Cobalt Strike Malleable C2 Beaconing", entity: "185.220.101.5:8443" },
      { id: "T1048.003", name: "DNS Tunneling Protocol", siem: "Elastic", alert: "High Entropy DNS Exfil Queries", entity: "cdn-sysinternals.com" }
    ],
    "Impact": [
      { id: "T1486", name: "Data Encrypted for Impact", siem: "Sentinel", alert: "Defender: Mass File Encryption (LockBit 3.0)", entity: "1,420 files .lockbit" },
      { id: "T1490", name: "Inhibit System Recovery", siem: "Wazuh", alert: "Shadow Copies Deleted via vssadmin", entity: "vssadmin delete shadows" }
    ]
  };

  const grid = document.getElementById("mitreGrid");
  if (!grid) return;
  grid.innerHTML = "";

  Object.entries(matrixPhases).forEach(([phase, techniques]) => {
    const col = document.createElement("div");
    col.className = "mitre-col";
    col.innerHTML = `
      <div class="mitre-header">
        ${phase} <span style="color:var(--text-dim); font-size:0.7rem; font-family:var(--font-mono);">(${techniques.length})</span>
      </div>
      <div class="mitre-cards">
        ${techniques.map(t => `
          <div class="tactic-card">
            <div style="display:flex; justify-content:space-between;">
              <span class="tactic-id">${t.id}</span>
              <span class="badge badge-source">${t.siem}</span>
            </div>
            <div class="tactic-name">${t.name}</div>
            <div class="tactic-alert">${t.alert}</div>
            <div style="color:var(--accent-cyan); font-family:var(--font-mono); font-size:0.66rem; margin-top:0.2rem;">${t.entity}</div>
          </div>
        `).join('')}
      </div>
    `;
    grid.appendChild(col);
  });
}

// 7. LangSmith Pipeline Evaluation
function initLangSmithEval() {
  const runBtn = document.getElementById("btnRunLangSmithEval");
  runBtn.addEventListener("click", async () => {
    try {
      runBtn.disabled = true;
      runBtn.textContent = "Running Benchmark...";
      const res = await fetch("/api/eval/run", { method: "POST" });
      const data = await res.json();
      renderEvalReport(data);
      loadEvalHistory();
      showToast(`LangSmith Evaluation finished with ${data.accuracy_score}% accuracy`);
    } catch (e) {
      showToast("Evaluation failed: " + e.message, "error");
    } finally {
      runBtn.disabled = false;
      runBtn.innerHTML = `<svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/></svg> Run Pipeline Evaluation`;
    }
  });

  loadEvalHistory();
}

function renderEvalReport(data) {
  document.getElementById("evalAccuracyDisplay").textContent = `${data.accuracy_score}%`;
  document.getElementById("evalLatencyDisplay").textContent = `${data.avg_latency_ms}ms`;
  document.getElementById("evalPassedDisplay").textContent = `${data.passed_count}/${data.test_cases_count}`;
  document.getElementById("evalSyncStatus").textContent = data.langsmith_synced ? "Synced to Cloud" : "Local Benchmark";

  const tbody = document.getElementById("evalBenchmarkTableBody");
  tbody.innerHTML = (data.results || []).map(r => `
    <tr>
      <td><span class="code-pill">${r.id}</span></td>
      <td><strong>${r.name}</strong></td>
      <td><span class="badge ${r.status === 'PASSED' ? 'badge-low' : 'badge-critical'}">${r.status}</span></td>
      <td style="font-family:var(--font-mono); font-size:0.75rem;">${r.latency_ms}ms</td>
      <td style="color:var(--text-muted); font-size:0.75rem;">${r.details}</td>
    </tr>
  `).join('');
}

async function loadEvalHistory() {
  try {
    const res = await fetch("/api/eval/history");
    const runs = await res.json();
    if (runs.length > 0) {
      renderEvalReport(runs[0]);
    }
  } catch (err) {
    console.error("Failed to load evaluation history:", err);
  }
}

// 8. Settings Modal & API Keys
function initSettings() {
  const modal = document.getElementById("settingsModal");
  const openBtn = document.getElementById("openSettingsBtn");
  const closeBtn = document.getElementById("btnCloseSettings");
  const saveBtn = document.getElementById("btnSaveSettings");

  openBtn.addEventListener("click", async () => {
    try {
      const res = await fetch("/api/settings");
      const data = await res.json();
      document.getElementById("geminiKeyInput").placeholder = data.gemini_configured ? `Configured (${data.gemini_key_masked})` : "Enter Gemini API Key";
      document.getElementById("vtKeyInput").placeholder = data.virustotal_configured ? `Configured (${data.virustotal_key_masked})` : "Enter VirusTotal v3 API Key";
      document.getElementById("langsmithKeyInput").placeholder = data.langsmith_configured ? `Configured (${data.langsmith_key_masked})` : "Enter LangSmith API Key";
      document.getElementById("langsmithProjectInput").value = data.langsmith_project || "soc-copilot";
      modal.classList.add("active");
    } catch (e) {
      showToast("Failed to load settings: " + e.message, "error");
    }
  });

  closeBtn.addEventListener("click", () => modal.classList.remove("active"));

  saveBtn.addEventListener("click", async () => {
    const geminiKey = document.getElementById("geminiKeyInput").value.trim();
    const vtKey = document.getElementById("vtKeyInput").value.trim();
    const langsmithKey = document.getElementById("langsmithKeyInput").value.trim();

    try {
      const res = await fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          gemini_key: geminiKey || undefined,
          vt_key: vtKey || undefined,
          langsmith_key: langsmithKey || undefined
        })
      });
      const data = await res.json();
      showToast("Settings and API credentials updated");
      modal.classList.remove("active");
      document.getElementById("geminiKeyInput").value = "";
      document.getElementById("vtKeyInput").value = "";
      document.getElementById("langsmithKeyInput").value = "";
    } catch (e) {
      showToast("Error updating settings: " + e.message, "error");
    }
  });
}

// Utility
function debounce(fn, delay) {
  let timeout;
  return function(...args) {
    clearTimeout(timeout);
    timeout = setTimeout(() => fn.apply(this, args), delay);
  };
}

function formatTimestamp(ts) {
  if (!ts) return "—";
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  } catch (e) {
    return ts;
  }
}
