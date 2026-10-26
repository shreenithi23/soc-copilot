// Multi-SIEM SOC Copilot Frontend Logic — Enterprise Operations Console
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

// Toast notification helper (No emojis, crisp status indicators)
function showToast(message, type = "success") {
  const container = document.getElementById("toastContainer");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <span style="font-weight:600; color: ${type === 'success' ? 'var(--color-success)' : 'var(--color-critical)'};">[${type === "success" ? "OK" : "ERR"}]</span>
    <span>${escapeHtml(message)}</span>
  `;
  container.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 3500);
}

// 1. Navigation Tabs
function initTabs() {
  const tabs = document.querySelectorAll(".nav-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => {
        t.classList.remove("active");
        t.setAttribute("aria-selected", "false");
      });
      tab.classList.add("active");
      tab.setAttribute("aria-selected", "true");

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

    const statTotalLogs = document.getElementById("statTotalLogs");
    const statCritical = document.getElementById("statCritical");
    const statVtMalicious = document.getElementById("statVtMalicious");
    const statVtCached = document.getElementById("statVtCached");

    if (statTotalLogs) statTotalLogs.textContent = data.total_logs || 0;
    if (statCritical) statCritical.textContent = data.critical_alerts || 0;
    if (statVtMalicious) statVtMalicious.textContent = data.vt_malicious || 0;
    if (statVtCached) statVtCached.textContent = data.vt_cached || 0;
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

  if (sendBtn) sendBtn.addEventListener("click", submitQuery);
  if (input) {
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        submitQuery();
      }
    });
  }

  if (newSessionBtn) {
    newSessionBtn.addEventListener("click", () => {
      currentSessionId = null;
      const chatMessages = document.getElementById("chatMessages");
      if (chatMessages) {
        chatMessages.innerHTML = `
          <div class="message-bubble assistant">
            <div class="avatar ai-avatar">AI</div>
            <div class="message-content-wrapper">
              <div class="message-meta">
                <span class="meta-sender">SOC Copilot</span>
                <span class="meta-sep">&bull;</span>
                <span class="meta-info">New Session Initialized</span>
              </div>
              <div class="message-text">
                <p>New investigation session started. Correlation engine and conversational memory are active.</p>
              </div>
            </div>
          </div>
        `;
      }
      const contextLogsList = document.getElementById("contextLogsList");
      const activeIocsList = document.getElementById("activeIocsList");
      if (contextLogsList) contextLogsList.innerHTML = `<div class="empty-state-text">No correlated logs associated with current query.</div>`;
      if (activeIocsList) activeIocsList.innerHTML = `<div class="empty-state-text">No active indicators in current prompt context.</div>`;
      loadSessions();
      showToast("New hunting investigation session initialized");
    });
  }

  // Quick investigation prompt buttons
  document.querySelectorAll(".prompt-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const prompt = btn.dataset.prompt;
      if (input && prompt) {
        input.value = prompt;
        submitQuery();
      }
    });
  });
}

async function loadSessions() {
  try {
    const res = await fetch("/api/chat/sessions");
    const sessions = await res.json();
    const list = document.getElementById("sessionsList");
    if (!list) return;
    list.innerHTML = "";

    sessions.forEach((s, idx) => {
      const item = document.createElement("div");
      item.className = `session-item ${s.id === currentSessionId || (!currentSessionId && idx === 0) ? "active" : ""}`;
      item.setAttribute("role", "option");
      item.innerHTML = `
        <div class="title">${escapeHtml(s.title || "Investigation Session")}</div>
        <div class="date">${new Date(s.updated_at).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})} &bull; ${escapeHtml(s.id.slice(0, 8))}</div>
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
    if (!chatMessages) return;
    chatMessages.innerHTML = "";

    if (history.length === 0) {
      chatMessages.innerHTML = `
        <div class="message-bubble assistant">
          <div class="avatar ai-avatar">AI</div>
          <div class="message-content-wrapper">
            <div class="message-meta">
              <span class="meta-sender">SOC Copilot</span>
              <span class="meta-sep">&bull;</span>
              <span class="meta-info">Ready</span>
            </div>
            <div class="message-text">
              <p>Investigation session loaded. Submit a query or select an action to analyze SIEM telemetry.</p>
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

  // Loading indicator
  const loadingId = "loading-" + Date.now();
  const chatMessages = document.getElementById("chatMessages");
  const loadingBubble = document.createElement("div");
  loadingBubble.id = loadingId;
  loadingBubble.className = "message-bubble assistant";
  loadingBubble.innerHTML = `
    <div class="avatar ai-avatar">AI</div>
    <div class="message-content-wrapper">
      <div class="message-meta"><span class="meta-sender">SOC Copilot</span> &bull; <span>Querying SIEM Telemetry &amp; VirusTotal...</span></div>
      <div class="message-text" style="color: var(--text-muted); font-family: var(--font-mono); font-size: 11px;">
        Executing multi-SIEM correlation and checking IOC threat indicators...
      </div>
    </div>
  `;
  if (chatMessages) {
    chatMessages.appendChild(loadingBubble);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

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
    appendChatMessageUI("assistant", `[ERROR] Failed to execute SOC Copilot query: ${err.message}`);
  }
}

function appendChatMessageUI(role, content, meta = {}) {
  const chatMessages = document.getElementById("chatMessages");
  if (!chatMessages) return;
  const bubble = document.createElement("div");
  bubble.className = `message-bubble ${role}`;

  const isAI = role === "assistant";
  const avatarText = isAI ? "AI" : "SOC";
  const avatarClass = isAI ? "ai-avatar" : "user-avatar";

  let metaText = isAI ? "SOC Copilot" : "Senior SOC Analyst";
  if (meta.model) metaText += ` &bull; ${escapeHtml(meta.model)}`;
  if (meta.latency) metaText += ` &bull; ${escapeHtml(String(meta.latency))}ms`;

  bubble.innerHTML = `
    <div class="avatar ${avatarClass}">${avatarText}</div>
    <div class="message-content-wrapper">
      <div class="message-meta">
        <span class="meta-sender">${metaText}</span>
      </div>
      <div class="message-text">${formatMarkdown(content)}</div>
    </div>
  `;

  chatMessages.appendChild(bubble);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Markdown formatter helper (zero emoji injection)
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
    .replace(/&gt; \[!TIP\]/gim, '<blockquote style="border-left-color: var(--color-low);">[TIP]')
    .replace(/&gt; \[!WARNING\]/gim, '<blockquote style="border-left-color: var(--color-medium);">[WARNING]')
    .replace(/&gt; \[!IMPORTANT\]/gim, '<blockquote style="border-left-color: var(--color-critical);">[IMPORTANT]')
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
  // Correlated Logs List
  const logsList = document.getElementById("contextLogsList");
  if (logsList) {
    if (!logs || logs.length === 0) {
      logsList.innerHTML = `<div class="empty-state-text">No correlated logs associated with current query.</div>`;
    } else {
      logsList.innerHTML = logs.map(l => `
        <div style="background: #080c14; padding: 4px 6px; border-left: 2px solid ${getSeverityColor(l.severity)}; border-radius: var(--radius-xs); margin-bottom: 3px; font-size: 11px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong style="font-family:var(--font-mono); font-size:10px;">${escapeHtml(l.siem_source)}</strong>
            <span class="tag tag-${(l.severity || 'low').toLowerCase()}">${escapeHtml(l.severity)}</span>
          </div>
          <div style="color:var(--text-secondary); font-size:11px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; margin: 1px 0;">${escapeHtml(l.alert_name)}</div>
          <div style="color:#38bdf8; font-family:var(--font-mono); font-size:10px;">
            ${escapeHtml(l.src_ip || 'N/A')} &rarr; ${escapeHtml(l.dest_ip || 'N/A')}
          </div>
        </div>
      `).join('');
    }
  }

  // Active IOCs & VirusTotal
  const iocsList = document.getElementById("activeIocsList");
  if (!iocsList) return;

  const ips = Object.entries(threatIntel?.ips || {});
  const hashes = Object.entries(threatIntel?.hashes || {});
  const domains = Object.entries(threatIntel?.domains || {});

  if (ips.length === 0 && hashes.length === 0 && domains.length === 0) {
    iocsList.innerHTML = `<div class="empty-state-text">No active indicators in current prompt context.</div>`;
    return;
  }

  let html = "";
  ips.forEach(([ip, info]) => {
    const isMal = info.malicious_count > 0;
    html += `
      <div class="ioc-entry ${isMal ? '' : 'clean'}">
        <span class="ioc-val" title="${escapeHtml(ip)}">${escapeHtml(ip)}</span>
        <span class="tag ${isMal ? 'tag-critical' : 'tag-clean'}">
          ${isMal ? `VT: ${info.malicious_count}/72` : 'CLEAN'}
        </span>
      </div>
    `;
  });
  hashes.forEach(([h, info]) => {
    const isMal = info.malicious_count > 0;
    html += `
      <div class="ioc-entry ${isMal ? '' : 'clean'}">
        <span class="ioc-val" title="${escapeHtml(h)}">${escapeHtml(h.slice(0, 16))}...</span>
        <span class="tag ${isMal ? 'tag-critical' : 'tag-clean'}">
          ${isMal ? `VT: ${info.malicious_count}/72` : 'CLEAN'}
        </span>
      </div>
    `;
  });
  domains.forEach(([d, info]) => {
    const isMal = info.malicious_count > 0;
    html += `
      <div class="ioc-entry ${isMal ? '' : 'clean'}">
        <span class="ioc-val" title="${escapeHtml(d)}">${escapeHtml(d)}</span>
        <span class="tag ${isMal ? 'tag-critical' : 'tag-clean'}">
          ${isMal ? `VT: ${info.malicious_count}/72` : 'CLEAN'}
        </span>
      </div>
    `;
  });
  iocsList.innerHTML = html;
}

function getSeverityColor(sev) {
  const s = (sev || "").toUpperCase();
  if (s === "CRITICAL") return "var(--color-critical)";
  if (s === "HIGH") return "var(--color-high)";
  if (s === "MEDIUM") return "var(--color-medium)";
  if (s === "LOW") return "var(--color-low)";
  return "var(--color-info)";
}

// 4. Multi-SIEM Log Explorer
function initLogExplorer() {
  const sourceFilter = document.getElementById("logSourceFilter");
  const sevFilter = document.getElementById("logSeverityFilter");
  const searchInput = document.getElementById("logSearchInput");
  const reloadSeedBtn = document.getElementById("reloadSeedBtn");
  const ingestModalBtn = document.getElementById("ingestModalBtn");

  if (sourceFilter) sourceFilter.addEventListener("change", () => loadLogs());
  if (sevFilter) sevFilter.addEventListener("change", () => loadLogs());
  if (searchInput) searchInput.addEventListener("input", debounce(() => loadLogs(), 300));

  if (reloadSeedBtn) {
    reloadSeedBtn.addEventListener("click", async () => {
      try {
        const res = await fetch("/api/logs/seed", { method: "POST" });
        const data = await res.json();
        showToast(`Reset Multi-SIEM dataset: Loaded ${data.seeded_count} attack events`);
        refreshTelemetry();
        loadLogs();
        loadThreatIntelHub();
        renderMitreMatrix();
      } catch (err) {
        showToast("Failed to reset dataset: " + err.message, "error");
      }
    });
  }

  const ingestModal = document.getElementById("ingestModal");
  if (ingestModalBtn && ingestModal) {
    ingestModalBtn.addEventListener("click", () => {
      ingestModal.classList.add("active");
    });
  }

  // Modal dismiss buttons
  const btnCloseIngestModal = document.getElementById("btnCloseIngestModal");
  const btnCancelIngest = document.getElementById("btnCancelIngest");
  const closeIngestModal = () => { if (ingestModal) ingestModal.classList.remove("active"); };
  if (btnCloseIngestModal) btnCloseIngestModal.addEventListener("click", closeIngestModal);
  if (btnCancelIngest) btnCancelIngest.addEventListener("click", closeIngestModal);

  // Ingestion Modal submit
  const btnExecuteIngest = document.getElementById("btnExecuteIngest");
  if (btnExecuteIngest) {
    btnExecuteIngest.addEventListener("click", async () => {
      const formatType = document.getElementById("ingestFormatSelect").value;
      const rawText = document.getElementById("ingestRawText").value.trim();
      const fileInput = document.getElementById("ingestFileInput");

      if (fileInput && fileInput.files.length > 0) {
        const formData = new FormData();
        formData.append("file", fileInput.files[0]);
        formData.append("format_type", formatType);
        try {
          const res = await fetch("/api/logs/upload", { method: "POST", body: formData });
          const data = await res.json();
          showToast(`Ingested ${data.ingested_count} logs from ${data.filename}`);
          closeIngestModal();
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
          closeIngestModal();
          refreshTelemetry();
          loadLogs();
        } catch (e) {
          showToast("Ingestion failed: " + e.message, "error");
        }
      } else {
        showToast("Select a log file or enter raw text to ingest", "error");
      }
    });
  }
}

async function loadLogs() {
  const source = document.getElementById("logSourceFilter")?.value || "all";
  const severity = document.getElementById("logSeverityFilter")?.value || "all";
  const search = document.getElementById("logSearchInput")?.value || "";

  try {
    const url = `/api/logs?source=${encodeURIComponent(source)}&severity=${encodeURIComponent(severity)}&search=${encodeURIComponent(search)}&limit=100`;
    const res = await fetch(url);
    const data = await res.json();
    activeLogs = data.logs || [];

    const counter = document.getElementById("logCountBadge");
    if (counter) counter.textContent = `${data.total || 0} Events`;

    const tbody = document.getElementById("logTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (activeLogs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 24px; color: var(--text-muted);">No security events match the specified filter criteria.</td></tr>`;
      return;
    }

    activeLogs.forEach(log => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><span class="tag tag-source">${escapeHtml(log.siem_source)}</span></td>
        <td><span class="tag tag-${(log.severity || 'low').toLowerCase()}">${escapeHtml(log.severity)}</span></td>
        <td class="text-mono" style="font-size:11px; color:var(--text-muted);">${formatTimestamp(log.timestamp)}</td>
        <td><strong style="color:var(--text-primary);">${escapeHtml(log.alert_name)}</strong></td>
        <td>
          <span class="code-snippet">${escapeHtml(log.src_ip || '—')}${log.src_port ? ':' + escapeHtml(String(log.src_port)) : ''}</span>
          <span style="color:var(--text-muted);">&rarr;</span>
          <span class="code-snippet">${escapeHtml(log.dest_ip || '—')}${log.dest_port ? ':' + escapeHtml(String(log.dest_port)) : ''}</span>
        </td>
        <td><span class="text-mono text-cyan" style="font-size:11px;">${escapeHtml(log.user || '—')}</span></td>
        <td style="text-align: center;">
          <button class="btn btn-secondary btn-xs view-log-btn" data-id="${escapeHtml(log.id)}">Inspect</button>
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
  if (!modal) return;

  const inspectSiemSource = document.getElementById("inspectSiemSource");
  const inspectSeverity = document.getElementById("inspectSeverity");
  const inspectAlertName = document.getElementById("inspectAlertName");
  const inspectTimestamp = document.getElementById("inspectTimestamp");
  const inspectSrcDest = document.getElementById("inspectSrcDest");
  const inspectUser = document.getElementById("inspectUser");
  const inspectFileHash = document.getElementById("inspectFileHash");
  const inspectDomain = document.getElementById("inspectDomain");
  const inspectDetailsJson = document.getElementById("inspectDetailsJson");
  const inspectRawLog = document.getElementById("inspectRawLog");

  if (inspectSiemSource) inspectSiemSource.textContent = log.siem_source;
  if (inspectSeverity) {
    inspectSeverity.textContent = log.severity;
    inspectSeverity.className = `tag tag-${(log.severity || 'low').toLowerCase()}`;
  }
  if (inspectAlertName) inspectAlertName.textContent = log.alert_name;
  if (inspectTimestamp) inspectTimestamp.textContent = log.timestamp;
  if (inspectSrcDest) inspectSrcDest.textContent = `${log.src_ip || 'N/A'}:${log.src_port || ''} \u2192 ${log.dest_ip || 'N/A'}:${log.dest_port || ''}`;
  if (inspectUser) inspectUser.textContent = log.user || 'N/A';
  if (inspectFileHash) inspectFileHash.textContent = log.file_hash || 'N/A';
  if (inspectDomain) inspectDomain.textContent = log.domain || 'N/A';

  if (inspectDetailsJson) inspectDetailsJson.textContent = JSON.stringify(log.details || {}, null, 2);
  if (inspectRawLog) inspectRawLog.textContent = log.raw_log || 'N/A';

  modal.classList.add("active");

  const closeInspector = () => modal.classList.remove("active");
  const btnCloseInspector = document.getElementById("btnCloseInspector");
  const btnDismissInspector = document.getElementById("btnDismissInspector");
  if (btnCloseInspector) btnCloseInspector.onclick = closeInspector;
  if (btnDismissInspector) btnDismissInspector.onclick = closeInspector;
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
      scanBtn.textContent = "Analyze Indicator";
    }
  };

  if (scanBtn) scanBtn.addEventListener("click", runScan);
  if (input) {
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") runScan();
    });
  }
}

function renderVtScanResult(data) {
  const container = document.getElementById("vtScanResultContainer");
  if (!container) return;
  container.style.display = "flex";

  const total = (data.malicious_count || 0) + (data.suspicious_count || 0) + (data.harmless_count || 0) + (data.undetected_count || 0) || 72;
  const mal = data.malicious_count || 0;

  const vtIndicatorDisplay = document.getElementById("vtIndicatorDisplay");
  const vtIocType = document.getElementById("vtIocType");
  const vtScoreDisplay = document.getElementById("vtScoreDisplay");
  const vtReputationNum = document.getElementById("vtReputationNum");
  const vtSourceLabel = document.getElementById("vtSourceLabel");

  if (vtIndicatorDisplay) vtIndicatorDisplay.textContent = data.indicator;
  if (vtIocType) vtIocType.textContent = (data.ioc_type || "IOC").toUpperCase();
  if (vtScoreDisplay) {
    vtScoreDisplay.textContent = `${mal} / ${total}`;
    vtScoreDisplay.className = mal > 0 ? "metric-val text-danger" : "metric-val text-success";
  }
  if (vtReputationNum) vtReputationNum.textContent = data.reputation || 0;
  if (vtSourceLabel) vtSourceLabel.textContent = data.source || "VirusTotal v3";

  // Render tags
  const tagsContainer = document.getElementById("vtTagsContainer");
  if (tagsContainer) {
    tagsContainer.innerHTML = (data.tags || []).map(t => `<span class="tag tag-medium">${escapeHtml(t)}</span>`).join(' ');
  }

  // Render engine detections
  const engineDiv = document.getElementById("vtEngineDetections");
  if (engineDiv) {
    const engines = Object.entries(data.engine_details || {});
    if (engines.length === 0) {
      engineDiv.innerHTML = `<span style="color:var(--text-muted); font-size:11px;">Zero security vendor detections flagged for this indicator.</span>`;
    } else {
      engineDiv.innerHTML = engines.map(([eng, det]) => `
        <div class="engine-row">
          <span style="color:var(--text-primary); font-weight:600;">${escapeHtml(eng)}</span>
          <span class="text-danger">${escapeHtml(det)}</span>
        </div>
      `).join('');
    }
  }
}

async function loadThreatIntelHub() {
  try {
    const res = await fetch("/api/threat-intel/cached");
    allCachedIntel = await res.json();
    const tbody = document.getElementById("cachedIntelTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (allCachedIntel.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:18px; color:var(--text-muted);">Local threat intelligence registry is empty. Query an indicator above.</td></tr>`;
      return;
    }

    allCachedIntel.forEach(item => {
      const isMal = item.malicious_count > 0;
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><span class="tag tag-source">${escapeHtml(item.ioc_type)}</span></td>
        <td><strong class="text-mono" style="color:var(--text-primary); font-size:11px;">${escapeHtml(item.indicator)}</strong></td>
        <td>
          <span class="tag ${isMal ? 'tag-critical' : 'tag-clean'}">
            ${isMal ? `${item.malicious_count} Malicious` : 'Clean (0)'}
          </span>
        </td>
        <td class="text-mono" style="font-size:11px;">${escapeHtml(String(item.reputation))}</td>
        <td>
          ${(item.tags || []).slice(0, 3).map(t => `<span class="tag tag-medium">${escapeHtml(t)}</span>`).join(' ')}
        </td>
        <td style="text-align: center;">
          <button class="btn btn-secondary btn-xs lookup-cached-btn" data-ioc="${escapeHtml(item.indicator)}">Inspect</button>
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
  const matrixPhases = {
    "Initial Access": [
      { id: "T1566.002", name: "Spearphishing Link", siem: "Sentinel", alert: "Office 365: Phishing Link Clicked", entity: "victim_jdoe@enterprise.corp" }
    ],
    "Execution": [
      { id: "T1059.001", name: "PowerShell EncodedCommand", siem: "Elastic", alert: "Obfuscated PowerShell Execution", entity: "WINWORD.EXE \u2192 powershell.exe" }
    ],
    "Credential Access": [
      { id: "T1003.001", name: "LSASS Memory Dump", siem: "Splunk", alert: "Mimikatz sekurlsa Ticket Request", entity: "victim_jdoe / krbtgt" },
      { id: "T1110.001", name: "SSH Password Spray", siem: "Wazuh", alert: "SSH Brute-force & Sudo Elevation", entity: "root / 45.33.32.156" }
    ],
    "Lateral Movement": [
      { id: "T1550.002", name: "Pass the Hash (SMB)", siem: "QRadar", alert: "PsExec / WMI Domain Controller Access", entity: "10.0.4.15 \u2192 10.0.4.200" }
    ],
    "Command & Control": [
      { id: "T1071.001", name: "Web Protocols / C2 Beacon", siem: "Splunk", alert: "Cobalt Strike Malleable C2 Beaconing", entity: "185.220.101.5:8443" },
      { id: "T1048.003", name: "DNS Tunneling Protocol", siem: "Elastic", alert: "High Entropy DNS Exfil Queries", entity: "cdn-sysinternals.com" }
    ],
    "Impact": [
      { id: "T1486", name: "Data Encrypted for Impact", siem: "Sentinel", alert: "Defender: Mass File Encryption (LockBit)", entity: "1,420 files .lockbit" },
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
        ${escapeHtml(phase)} <span style="color:var(--text-muted); font-size:10px;">(${techniques.length})</span>
      </div>
      <div class="mitre-cards">
        ${techniques.map(t => `
          <div class="tactic-card">
            <div class="tactic-header-row">
              <span class="tactic-id">${escapeHtml(t.id)}</span>
              <span class="tag tag-source">${escapeHtml(t.siem)}</span>
            </div>
            <div class="tactic-name">${escapeHtml(t.name)}</div>
            <div class="tactic-alert">${escapeHtml(t.alert)}</div>
            <div class="tactic-entity">${escapeHtml(t.entity)}</div>
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
  if (runBtn) {
    runBtn.addEventListener("click", async () => {
      try {
        runBtn.disabled = true;
        runBtn.textContent = "Running Benchmark...";
        const res = await fetch("/api/eval/run", { method: "POST" });
        const data = await res.json();
        renderEvalReport(data);
        loadEvalHistory();
        showToast(`LangSmith Benchmark complete: ${data.accuracy_score}% Accuracy`);
      } catch (e) {
        showToast("Evaluation failed: " + e.message, "error");
      } finally {
        runBtn.disabled = false;
        runBtn.textContent = "Run Pipeline Evaluation";
      }
    });
  }

  loadEvalHistory();
}

function renderEvalReport(data) {
  const evalAccuracyDisplay = document.getElementById("evalAccuracyDisplay");
  const evalLatencyDisplay = document.getElementById("evalLatencyDisplay");
  const evalPassedDisplay = document.getElementById("evalPassedDisplay");
  const evalSyncStatus = document.getElementById("evalSyncStatus");

  if (evalAccuracyDisplay) evalAccuracyDisplay.textContent = `${data.accuracy_score}%`;
  if (evalLatencyDisplay) evalLatencyDisplay.textContent = `${data.avg_latency_ms}ms`;
  if (evalPassedDisplay) evalPassedDisplay.textContent = `${data.passed_count} / ${data.test_cases_count}`;
  if (evalSyncStatus) evalSyncStatus.textContent = data.langsmith_synced ? "Synced to Cloud" : "Local Benchmark";

  const tbody = document.getElementById("evalBenchmarkTableBody");
  if (!tbody) return;
  tbody.innerHTML = (data.results || []).map(r => `
    <tr>
      <td><span class="code-snippet">${escapeHtml(r.id)}</span></td>
      <td><strong>${escapeHtml(r.name)}</strong></td>
      <td><span class="tag ${r.status === 'PASSED' ? 'tag-clean' : 'tag-critical'}">${escapeHtml(r.status)}</span></td>
      <td class="text-mono" style="font-size:11px;">${escapeHtml(String(r.latency_ms))}ms</td>
      <td style="color:var(--text-secondary); font-size:11px;">${escapeHtml(r.details)}</td>
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
  const cancelBtn = document.getElementById("btnCancelSettings");
  const saveBtn = document.getElementById("btnSaveSettings");

  const closeModal = () => { if (modal) modal.classList.remove("active"); };

  if (openBtn) {
    openBtn.addEventListener("click", async () => {
      try {
        const res = await fetch("/api/settings");
        const data = await res.json();
        const geminiInput = document.getElementById("geminiKeyInput");
        const vtInput = document.getElementById("vtKeyInput");
        const langsmithInput = document.getElementById("langsmithKeyInput");
        const projectInput = document.getElementById("langsmithProjectInput");

        if (geminiInput) geminiInput.placeholder = data.gemini_configured ? `Configured (${data.gemini_key_masked})` : "Enter Gemini API Key";
        if (vtInput) vtInput.placeholder = data.virustotal_configured ? `Configured (${data.virustotal_key_masked})` : "Enter VirusTotal API Key";
        if (langsmithInput) langsmithInput.placeholder = data.langsmith_configured ? `Configured (${data.langsmith_key_masked})` : "Enter LangSmith API Key";
        if (projectInput) projectInput.value = data.langsmith_project || "soc-copilot";

        if (modal) modal.classList.add("active");
      } catch (e) {
        showToast("Failed to load settings: " + e.message, "error");
      }
    });
  }

  if (closeBtn) closeBtn.addEventListener("click", closeModal);
  if (cancelBtn) cancelBtn.addEventListener("click", closeModal);

  if (saveBtn) {
    saveBtn.addEventListener("click", async () => {
      const geminiKey = document.getElementById("geminiKeyInput")?.value.trim();
      const vtKey = document.getElementById("vtKeyInput")?.value.trim();
      const langsmithKey = document.getElementById("langsmithKeyInput")?.value.trim();

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
        await res.json();
        showToast("API credentials updated successfully");
        closeModal();
        if (document.getElementById("geminiKeyInput")) document.getElementById("geminiKeyInput").value = "";
        if (document.getElementById("vtKeyInput")) document.getElementById("vtKeyInput").value = "";
        if (document.getElementById("langsmithKeyInput")) document.getElementById("langsmithKeyInput").value = "";
      } catch (e) {
        showToast("Error updating settings: " + e.message, "error");
      }
    });
  }
}

// Utilities
function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

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
