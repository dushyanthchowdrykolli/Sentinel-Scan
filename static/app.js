/**
 * static/app.js
 *
 * Single-file vanilla JavaScript for the Sentinel Scan SPA.
 *
 * Screens managed:
 *   new-scan      → #screen-new-scan
 *   progress      → #screen-progress
 *   results       → #screen-results
 *   finding       → #screen-finding
 *   integrity     → #screen-integrity
 *   past-scans    → #screen-past-scans
 *
 * All API calls go to /api/...
 * No frameworks, no build step.
 */

"use strict";

/* ==========================================================================
   State
   ========================================================================== */
const state = {
  currentScreen: "new-scan",
  currentScanId: null,      // integer
  currentFindings: [],      // array of finding objects from API
  activeSeverityFilter: "all",
  searchQuery: "",
};

/* ==========================================================================
   Screen navigation
   ========================================================================== */
function showScreen(name) {
  // Deactivate all screens
  document.querySelectorAll(".screen").forEach((el) => {
    el.classList.remove("active");
    el.setAttribute("aria-hidden", "true");
  });

  // Deactivate all nav buttons
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.classList.remove("active");
    btn.removeAttribute("aria-current");
  });

  // Activate target screen
  const screenEl = document.getElementById(`screen-${name}`);
  if (screenEl) {
    screenEl.classList.add("active");
    screenEl.removeAttribute("aria-hidden");
  }

  // Activate matching nav button
  const navBtn = document.querySelector(`.nav-btn[data-screen="${name}"]`);
  if (navBtn) {
    navBtn.classList.add("active");
    navBtn.setAttribute("aria-current", "page");
  }

  state.currentScreen = name;
}

/* ==========================================================================
   Helpers
   ========================================================================== */
function escHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function severityBadge(severity) {
  const cls = `badge-${severity.toLowerCase()}`;
  return `<span class="badge ${cls}">${escHtml(severity)}</span>`;
}

function severityBar(severity) {
  const cls = `bar-${severity.toLowerCase()}`;
  return `<div class="finding-severity-bar ${cls}" aria-hidden="true"></div>`;
}

function formatDate(isoStr) {
  if (!isoStr) return "—";
  try {
    return new Date(isoStr).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  } catch {
    return isoStr;
  }
}

function isPrivateOrLocal(url) {
  try {
    const parsed = new URL(url);
    const h = parsed.hostname;
    return (
      h === "localhost" ||
      h === "127.0.0.1" ||
      h === "::1" ||
      h.startsWith("192.168.") ||
      h.startsWith("10.") ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(h)
    );
  } catch {
    return false;
  }
}

/* ==========================================================================
   New Scan form
   ========================================================================== */
function initNewScanForm() {
  const form = document.getElementById("scan-form");
  const urlInput = document.getElementById("target-url");
  const authGroup = document.getElementById("auth-group");
  const authCheckbox = document.getElementById("authorized");
  const errorEl = document.getElementById("form-error");
  const startBtn = document.getElementById("start-btn");

  // Show authorization checkbox when URL is external
  urlInput.addEventListener("input", () => {
    const val = urlInput.value.trim();
    if (val && !isPrivateOrLocal(val)) {
      authGroup.hidden = false;
    } else {
      authGroup.hidden = true;
      authCheckbox.checked = false;
    }
    errorEl.hidden = true;
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    errorEl.hidden = true;

    const url = urlInput.value.trim();
    if (!url) {
      showError(errorEl, "Please enter a target URL.");
      return;
    }

    const isExternal = !isPrivateOrLocal(url);
    if (isExternal && !authCheckbox.checked) {
      authGroup.hidden = false;
      showError(
        errorEl,
        "This target is not on a private network. Tick the authorization checkbox to proceed."
      );
      return;
    }

    startBtn.disabled = true;
    startBtn.textContent = "Starting…";

    try {
      const resp = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_url: url,
          authorized: authCheckbox.checked,
        }),
      });

      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        throw new Error(data.detail || `HTTP ${resp.status}`);
      }

      const scan = await resp.json();
      state.currentScanId = scan.id;
      startProgressScreen(scan);
    } catch (err) {
      showError(errorEl, `Could not start scan: ${err.message}`);
    } finally {
      startBtn.disabled = false;
      startBtn.textContent = "Start Scan";
    }
  });
}

function showError(el, msg) {
  el.textContent = msg;
  el.hidden = false;
}

/* ==========================================================================
   Progress screen
   ========================================================================== */
const MODULES = [
  "Security Headers",
  "Cookie Flags",
  "TLS / Certificate",
  "Server Banners",
  "Exposed Paths",
  "CORS Misconfiguration",
  "CSRF Token Check",
  "Reflected XSS Probe",
  "SQL Injection Probe",
];
const TOTAL_MODULES = MODULES.length;

function startProgressScreen(scan) {
  showScreen("progress");

  const targetLabel = document.getElementById("progress-target-label");
  targetLabel.textContent = `Scanning: ${scan.target_url}`;

  const bar = document.getElementById("progress-bar");
  const barWrapper = document.getElementById("progress-bar-wrapper");
  bar.style.width = "0%";
  barWrapper.setAttribute("aria-valuenow", "0");

  const modulesContainer = document.getElementById("progress-modules");
  modulesContainer.innerHTML = "";

  // Render all module rows in pending state
  const moduleEls = {};
  MODULES.forEach((name) => {
    const row = document.createElement("div");
    row.className = "module-row";
    row.id = `module-row-${name.replace(/\s+/g, "-")}`;
    row.innerHTML = `
      <div class="module-status-icon pending" aria-hidden="true"></div>
      <span class="module-name">${escHtml(name)}</span>
      <span class="module-finding-count" aria-live="polite"></span>
    `;
    modulesContainer.appendChild(row);
    moduleEls[name] = row;
  });

  const liveFindingsWrapper = document.getElementById("live-findings-wrapper");
  const liveFindingsList = document.getElementById("live-findings-list");
  liveFindingsWrapper.hidden = true;
  liveFindingsList.innerHTML = "";

  let completedModules = 0;
  let allFindings = [];

  // Open SSE connection
  const evtSource = new EventSource(`/api/scans/${scan.id}/progress`);

  evtSource.onmessage = (event) => {
    let data;
    try {
      data = JSON.parse(event.data);
    } catch {
      return;
    }

    // Terminal event
    if (data.type === "done") {
      evtSource.close();
      bar.style.width = "100%";
      barWrapper.setAttribute("aria-valuenow", TOTAL_MODULES);

      // Mark any remaining module as done
      MODULES.forEach((name) => {
        const row = moduleEls[name];
        if (row) {
          const icon = row.querySelector(".module-status-icon");
          if (icon && icon.classList.contains("pending")) {
            icon.className = "module-status-icon done";
          }
        }
      });

      // After short delay, switch to results
      setTimeout(() => {
        loadResultsScreen(scan.id);
      }, 600);
      return;
    }

    // Module progress event
    const moduleName = data.module;
    const findings = data.findings || [];

    // Mark current module as done
    const row = moduleEls[moduleName];
    if (row) {
      const icon = row.querySelector(".module-status-icon");
      if (icon) icon.className = "module-status-icon done";
      const countEl = row.querySelector(".module-finding-count");
      if (countEl) {
        countEl.textContent =
          findings.length > 0
            ? `${findings.length} finding${findings.length !== 1 ? "s" : ""}`
            : "";
      }
    }

    // Mark next module as running
    completedModules++;
    const pct = Math.round((completedModules / TOTAL_MODULES) * 100);
    bar.style.width = pct + "%";
    barWrapper.setAttribute("aria-valuenow", completedModules);

    const nextModule = MODULES[completedModules];
    if (nextModule && moduleEls[nextModule]) {
      const nextIcon = moduleEls[nextModule].querySelector(".module-status-icon");
      if (nextIcon) nextIcon.className = "module-status-icon running";
    }

    // Append new findings
    if (findings.length > 0) {
      liveFindingsWrapper.hidden = false;
      findings.forEach((f) => {
        allFindings.push(f);
        const el = createFindingRowEl(f, scan.id);
        liveFindingsList.appendChild(el);
      });
    }
  };

  evtSource.onerror = () => {
    evtSource.close();
    // Fall back to polling
    setTimeout(() => {
      loadResultsScreen(scan.id);
    }, 1000);
  };

  // Mark first module as running
  const firstRow = moduleEls[MODULES[0]];
  if (firstRow) {
    const icon = firstRow.querySelector(".module-status-icon");
    if (icon) icon.className = "module-status-icon running";
  }
}

/* ==========================================================================
   Results screen
   ========================================================================== */
async function loadResultsScreen(scanId) {
  showScreen("results");
  state.currentScanId = scanId;

  const titleEl = document.getElementById("results-title");
  const subtitleEl = document.getElementById("results-subtitle");
  titleEl.textContent = "Loading results…";
  subtitleEl.textContent = "";

  try {
    const [scan, findings] = await Promise.all([
      fetch(`/api/scans/${scanId}`).then((r) => r.json()),
      fetch(`/api/scans/${scanId}/findings`).then((r) => r.json()),
    ]);

    state.currentFindings = findings;

    titleEl.textContent = "Scan Results";
    subtitleEl.textContent = `${scan.target_url} — ${findings.length} finding${findings.length !== 1 ? "s" : ""}`;

    // Severity summary
    renderSeveritySummary(findings);

    // Render timings if available
    renderExecutionTimings(scan);

    // Render filtered list
    renderFindingsList();

    // Wire up export buttons
    document.getElementById("export-json-btn").onclick = () => {
      window.location.href = `/api/scans/${scanId}/export/json`;
    };
    document.getElementById("export-html-btn").onclick = () => {
      window.location.href = `/api/scans/${scanId}/export/html`;
    };
    document.getElementById("verify-integrity-btn").onclick = async () => {
      showScreen("integrity");
      await runIntegrityCheck(scanId);
    };
  } catch (err) {
    titleEl.textContent = "Error loading results";
    subtitleEl.textContent = err.message;
  }
}

function renderExecutionTimings(scan) {
  const timingCard = document.getElementById("results-timing-card");
  const totalDurationEl = document.getElementById("results-total-duration");
  const timingGrid = document.getElementById("results-timing-grid");
  const toggleBtn = document.getElementById("timing-toggle-btn");
  const detailsEl = document.getElementById("results-timing-details");

  if (!timingCard || !scan.scan_meta) {
    if (timingCard) timingCard.hidden = true;
    return;
  }

  let meta = {};
  try {
    meta = typeof scan.scan_meta === "string" ? JSON.parse(scan.scan_meta) : scan.scan_meta;
  } catch (e) {
    timingCard.hidden = true;
    return;
  }

  if (!meta.module_durations) {
    timingCard.hidden = true;
    return;
  }

  timingCard.hidden = false;
  totalDurationEl.textContent = `${meta.total_duration_seconds}s total`;

  timingGrid.innerHTML = Object.entries(meta.module_durations)
    .map(
      ([mod, dur]) => `
      <div style="background:var(--gray-50); padding:6px 10px; border-radius:var(--radius-sm); border:1px solid var(--border); display:flex; justify-content:space-between;">
        <span style="color:var(--gray-700); font-weight:500;">${escHtml(mod)}</span>
        <span style="font-family:ui-monospace,monospace; color:var(--navy);">${dur}s</span>
      </div>`
    )
    .join("");

  toggleBtn.onclick = () => {
    detailsEl.hidden = !detailsEl.hidden;
  };
}

function renderSeveritySummary(findings) {
  const container = document.getElementById("severity-summary");
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  findings.forEach((f) => {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  });

  container.innerHTML = ["Critical", "High", "Medium", "Low", "Info"]
    .map(
      (sev) => `
      <div class="sev-chip" role="listitem">
        ${severityBadge(sev)}
        <span class="sev-chip-count">${counts[sev]}</span>
      </div>`
    )
    .join("");
}

function renderFindingsList() {
  const list = document.getElementById("findings-list");
  const noMsg = document.getElementById("no-findings-msg");

  const filtered = state.currentFindings.filter((f) => {
    const matchSev =
      state.activeSeverityFilter === "all" ||
      f.severity === state.activeSeverityFilter;
    const q = state.searchQuery.toLowerCase();
    const matchSearch =
      !q ||
      f.title.toLowerCase().includes(q) ||
      f.category.toLowerCase().includes(q) ||
      f.affected_url.toLowerCase().includes(q) ||
      f.description.toLowerCase().includes(q);
    return matchSev && matchSearch;
  });

  list.innerHTML = "";
  if (filtered.length === 0) {
    noMsg.hidden = false;
  } else {
    noMsg.hidden = true;
    filtered.forEach((f) => {
      list.appendChild(createFindingRowEl(f, state.currentScanId));
    });
  }
}

function createFindingRowEl(f, scanId) {
  const div = document.createElement("div");
  div.className = "finding-row";
  div.setAttribute("tabindex", "0");
  div.setAttribute("role", "button");
  div.setAttribute(
    "aria-label",
    `${f.severity} finding: ${f.title}`
  );
  div.innerHTML = `
    ${severityBar(f.severity)}
    <div class="finding-row-body">
      <div class="finding-row-title">${escHtml(f.title)}</div>
      <div class="finding-row-meta">
        ${severityBadge(f.severity)}
        <span>${escHtml(f.category)}</span>
      </div>
      <div class="finding-row-url">${escHtml(f.affected_url)}</div>
    </div>
  `;

  const openDetail = () => showFindingDetail(f);
  div.addEventListener("click", openDetail);
  div.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      openDetail();
    }
  });

  return div;
}

/* ==========================================================================
   Filter and search wiring
   ========================================================================== */
function initFilterAndSearch() {
  document.getElementById("findings-search").addEventListener("input", (e) => {
    state.searchQuery = e.target.value;
    renderFindingsList();
  });

  document.getElementById("filter-pills").addEventListener("click", (e) => {
    const pill = e.target.closest(".pill");
    if (!pill) return;

    document.querySelectorAll(".pill").forEach((p) => p.classList.remove("active"));
    pill.classList.add("active");
    state.activeSeverityFilter = pill.dataset.severity;
    renderFindingsList();
  });
}

/* ==========================================================================
   Finding detail screen
   ========================================================================== */
function showFindingDetail(f) {
  showScreen("finding");

  const content = document.getElementById("finding-detail-content");
  content.innerHTML = `
    <h2 class="finding-detail-title">${escHtml(f.title)}</h2>

    <div class="meta-grid">
      <div class="meta-cell label">Severity</div>
      <div class="meta-cell">${severityBadge(f.severity)}</div>
      <div class="meta-cell label">Category</div>
      <div class="meta-cell">${escHtml(f.category)}</div>
      <div class="meta-cell label">Affected URL</div>
      <div class="meta-cell"><code>${escHtml(f.affected_url)}</code></div>
    </div>

    <div class="section-label">Description</div>
    <p style="font-size:.9375rem;color:var(--gray-700);margin-bottom:16px">
      ${escHtml(f.description)}
    </p>

    <div class="section-label">Evidence</div>
    <div class="evidence-block">${escHtml(f.evidence_raw)}</div>

    <div class="section-label">SHA-256 Evidence Hash</div>
    <div class="hash-display">${escHtml(f.evidence_hash)}</div>
    <p style="font-size:.8125rem;color:var(--text-secondary);margin-bottom:16px">
      This hash is computed from the evidence block above and recorded in the
      tamper-evident ledger at capture time. If the evidence text is altered, the
      hash will no longer match.
    </p>

    <div class="section-label">Remediation</div>
    <div class="remediation-block">${escHtml(f.remediation)}</div>
  `;
}

document.getElementById("back-to-results-btn").addEventListener("click", () => {
  showScreen("results");
});

/* ==========================================================================
   Integrity check screen
   ========================================================================== */
function initIntegrityScreen() {
  document.getElementById("run-integrity-btn").addEventListener("click", () => {
    runIntegrityCheck(null);
  });
}

async function runIntegrityCheck(scanId) {
  const resultEl = document.getElementById("integrity-result");
  const ledgerWrapper = document.getElementById("ledger-table-wrapper");

  resultEl.hidden = false;
  resultEl.className = "integrity-result";
  resultEl.innerHTML = `<p>Verifying chain…</p>`;

  try {
    const url = scanId
      ? `/api/scans/${scanId}/integrity`
      : `/api/integrity`;

    const resp = await fetch(url);
    const data = await resp.json();

    if (data.ok) {
      resultEl.className = "integrity-result pass";
      resultEl.innerHTML = `
        <h3>Chain Intact</h3>
        <p class="integrity-detail">${escHtml(data.message)}</p>
      `;
    } else {
      resultEl.className = "integrity-result fail";
      resultEl.innerHTML = `
        <h3>Integrity Violation Detected</h3>
        <p class="integrity-detail">${escHtml(data.message)}</p>
        ${
          data.first_broken_id
            ? `<p class="integrity-detail">First broken entry ID: <strong>#${data.first_broken_id}</strong></p>`
            : ""
        }
      `;
    }

    // Load ledger entries
    const ledgerUrl = scanId
      ? `/api/ledger?scan_id=${scanId}&limit=100`
      : `/api/ledger?limit=100`;
    const entries = await fetch(ledgerUrl).then((r) => r.json());
    renderLedgerTable(entries, data.first_broken_id);
    ledgerWrapper.hidden = false;
  } catch (err) {
    resultEl.className = "integrity-result fail";
    resultEl.innerHTML = `<h3>Error</h3><p>${escHtml(err.message)}</p>`;
  }
}

function renderLedgerTable(entries, brokenId) {
  const tbody = document.getElementById("ledger-tbody");
  tbody.innerHTML = "";

  if (!entries.length) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">No ledger entries found.</td></tr>`;
    return;
  }

  // Reverse to show newest first
  const sorted = [...entries].sort((a, b) => a.id - b.id);

  sorted.forEach((entry) => {
    const tr = document.createElement("tr");
    if (brokenId && entry.id >= brokenId) {
      tr.style.background = "#fff1f2";
    }
    tr.innerHTML = `
      <td>${entry.id}</td>
      <td class="mono">${escHtml(entry.timestamp.replace("T", " ").slice(0, 19))}</td>
      <td>${entry.scan_id ?? "—"}</td>
      <td><span class="action-tag">${escHtml(entry.action)}</span></td>
      <td class="mono">${escHtml(entry.entry_hash.slice(0, 24))}…</td>
    `;
    tbody.appendChild(tr);
  });
}

/* ==========================================================================
   Past scans screen
   ========================================================================== */
async function loadPastScans() {
  const list = document.getElementById("past-scans-list");
  const noMsg = document.getElementById("no-past-scans-msg");

  list.innerHTML = `<p class="text-muted text-sm" style="padding:16px">Loading…</p>`;

  try {
    const scans = await fetch("/api/scans").then((r) => r.json());

    list.innerHTML = "";
    if (!scans.length) {
      noMsg.hidden = false;
      return;
    }
    noMsg.hidden = true;

    scans.forEach((scan) => {
      const card = document.createElement("div");
      card.className = "scan-card";
      card.setAttribute("tabindex", "0");
      card.setAttribute("role", "button");
      card.setAttribute("aria-label", `Open scan ${scan.target_url}`);

      const dotClass =
        scan.status === "running"
          ? "dot-running"
          : scan.status === "done"
          ? "dot-done"
          : "dot-error";

      const statusLabel =
        scan.status === "running"
          ? "Running"
          : scan.status === "done"
          ? "Done"
          : "Error";

      card.innerHTML = `
        <div class="scan-status-dot ${dotClass}" title="${statusLabel}" aria-label="${statusLabel}"></div>
        <div class="scan-card-body">
          <div class="scan-card-url">${escHtml(scan.target_url)}</div>
          <div class="scan-card-meta">
            #${scan.id} &nbsp;·&nbsp;
            Started ${formatDate(scan.started_at)}
            ${scan.finished_at ? ` &nbsp;·&nbsp; Finished ${formatDate(scan.finished_at)}` : ""}
          </div>
        </div>
        <div class="scan-card-badge">
          <span class="badge ${scan.status === "done" ? "badge-info" : "badge-low"}">${statusLabel}</span>
        </div>
      `;

      const open = () => {
        if (scan.status === "running") {
          state.currentScanId = scan.id;
          // Re-attach progress screen (SSE will reconnect)
          startProgressScreen(scan);
        } else {
          loadResultsScreen(scan.id);
        }
      };

      card.addEventListener("click", open);
      card.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          open();
        }
      });

      list.appendChild(card);
    });
  } catch (err) {
    list.innerHTML = `<p class="text-muted text-sm" style="padding:16px">Error loading scans: ${escHtml(err.message)}</p>`;
  }
}

/* ==========================================================================
   Sidebar navigation
   ========================================================================== */
function initNavigation() {
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const screen = btn.dataset.screen;
      showScreen(screen);
      if (screen === "past-scans") {
        loadPastScans();
      }
      if (screen === "integrity") {
        // Reset integrity result
        const resultEl = document.getElementById("integrity-result");
        const ledgerWrapper = document.getElementById("ledger-table-wrapper");
        resultEl.hidden = true;
        ledgerWrapper.hidden = true;
      }
    });
  });
}

/* ==========================================================================
   Bootstrap
   ========================================================================== */
document.addEventListener("DOMContentLoaded", () => {
  initNavigation();
  initNewScanForm();
  initFilterAndSearch();
  initIntegrityScreen();
  showScreen("new-scan");
});
