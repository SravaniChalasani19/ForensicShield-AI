// HTML escaping for XSS prevention
function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ForensicShield AI Client-Side Application Controller

async function secureFetch(input, options = {}) {
    const headers = new Headers(options.headers || {});
    const method = (options.method || "GET").toUpperCase();
    const target = new URL(input, window.location.href);

    if (
        target.origin === window.location.origin &&
        ["POST", "PUT", "PATCH", "DELETE"].includes(method)
    ) {
        const token = document.querySelector(
            'meta[name="csrf-token"]'
        )?.content;

        if (token) {
            headers.set("X-CSRF-Token", token);
        }
    }

    return window.fetch(input, {
        ...options,
        headers: headers
    });
}

let state = {
  activeCaseId: null,
  activeCaseTitle: null,
  activeExaminer: "Forensic Examiner",
  currentPage: 1,
  perPage: 25,
  totalEvents: 0,
};

// Tab Switching
function switchTab(tabId) {
  document.querySelectorAll(".tab-content").forEach(el => el.classList.remove("active"));
  document.querySelectorAll(".tab-btn").forEach(el => el.classList.remove("active"));

  const targetTab = document.getElementById(tabId);
  const targetBtn = document.querySelector(`[data-tab="${tabId}"]`);

  if (targetTab) targetTab.classList.add("active");
  if (targetBtn) targetBtn.classList.add("active");

  if (tabId === "tab-evidence" && state.activeCaseId) {
    loadCaseEvidence();
  } else if (tabId === "tab-explorer" && state.activeCaseId) {
    loadCaseEvents();
  } else if (tabId === "tab-timeline" && state.activeCaseId) {
    loadCaseTimeline();
  } else if (tabId === "tab-reports" && state.activeCaseId) {
    loadCaseAudit();
  } else if (tabId === "tab-live") {
    if (livePollTimer) { clearInterval(livePollTimer); livePollTimer = null; }
  } else if (tabId === "tab-datasets") {
    loadDatasetsAudit();
  } else if (tabId === "tab-evaluation") {
    loadEvaluationDatasets();
    loadResearchResults();
  }
}

// Modal Management
function showModal(modalId) {
  const m = document.getElementById(modalId);
  if (m) m.classList.add("active");

  if (modalId === "modal-upload-evidence") {
    const inputCase = document.getElementById("upload-target-case-id");
    if (inputCase) {
      inputCase.value = state.activeCaseId || "Select active case first";
    }
  }
}

function closeModal(modalId) {
  const m = document.getElementById(modalId);
  if (m) m.classList.remove("active");
}

// Case Selection
function selectCase(caseId, title, examiner) {
  state.activeCaseId = caseId;
  state.activeCaseTitle = title;
  state.activeExaminer = examiner || "Forensic Examiner";

  try {
    sessionStorage.setItem("fs_active_case", JSON.stringify({
      caseId: caseId,
      title: title,
      examiner: examiner || "Forensic Examiner"
    }));
  } catch (e) {}

  const idDisp = document.getElementById("active-case-id-display");
  if (idDisp) idDisp.innerText = caseId;
  const titleDisp = document.getElementById("active-case-title");
  if (titleDisp) titleDisp.innerText = title;
  const exDisp = document.getElementById("active-case-examiner");
  if (exDisp) exDisp.innerText = examiner;

  const btnAnalysis = document.getElementById("btn-run-analysis");
  const btnReport = document.getElementById("btn-gen-report");
  if (btnAnalysis) btnAnalysis.disabled = false;
  if (btnReport) btnReport.disabled = false;

  loadCaseEvidence();
  loadCaseEvents();
  loadCaseTimeline();
  loadCaseAudit();
}

// Create Case

async function handleCreateCase(event) {
  event.preventDefault();

  const caseTitle = document
    .getElementById("input-case-title").value.trim();

  const desc = document
    .getElementById("input-case-desc").value.trim();

  try {
    const res = await secureFetch("/api/cases", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        case_title: caseTitle,
        description: desc
      })
    });

    const data = await res.json();

    if (res.ok && data.case) {
      const createdCase = data.case;

      alert(`Case ${createdCase.case_id} created successfully.`);

      closeModal("modal-new-case");

      selectCase(
        createdCase.case_id,
        createdCase.case_title,
        createdCase.examiner
      );

      loadDashboardCases();

    } else {
      alert(`Error creating case: ${data.message || "Unable to create case."}`);
    }

  } catch (err) {
    alert(`Request error: ${err.message}`);
  }
}


// Refresh Dashboard Cases without losing active case state
async function loadDashboardCases() {
  try {
    if (state.activeCaseId) {
      loadCaseEvidence();
      loadCaseEvents();
      loadCaseTimeline();
      loadCaseAudit();
    }
  } catch (e) {
    console.error(e);
  }
}

// Upload Evidence (Approved Public Demo Mode)
async function handleUploadEvidence(event) {
  event.preventDefault();
  if (!state.activeCaseId) {
    alert("Please select or create an active case first.");
    return;
  }

  const fixtureSelect = document.getElementById("demo-fixture-select");
  const fixtureId = fixtureSelect ? fixtureSelect.value : "public_demo_logs";
  const submitBtn = document.getElementById("btn-submit-upload");

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerText = "Verifying & Ingesting...";
  }

  try {
    const res = await secureFetch(`/api/cases/${state.activeCaseId}/evidence`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fixture_id: fixtureId }),
    });

    const data = await res.json();
    if (res.ok) {
      alert(`Demonstration Evidence Ingested Successfully!
Evidence ID: ${data.evidence_id}
SHA-256 Digest: ${data.sha256_hash}
Canonical Events Parsed: ${data.events_parsed}`);
      closeModal("modal-upload-evidence");
      loadCaseEvidence();
      loadCaseEvents();
      loadCaseTimeline();
      loadCaseAudit();
      loadDashboardCases();
    } else if (res.status === 409) {
      alert(`Duplicate Ingestion Notice:
${data.message}`);
    } else {
      alert(`Ingestion Notice (${res.status}):
${data.message || "Failed to ingest evidence."}`);
    }
  } catch (err) {
    alert(`Ingestion failed: ${err.message}`);
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerText = "Verify SHA-256 & Ingest";
    }
  }
}

// Load Case Evidence
async function loadCaseEvidence() {
  if (!state.activeCaseId) return;
  const tbody = document.getElementById("tbody-evidence-list");
  if (!tbody) return;

  try {
    const res = await secureFetch(`/api/cases/${state.activeCaseId}`);
    const data = await res.json();
    if (!res.ok) return;

    const list = data.evidence || [];
    if (!list.length) {
      tbody.innerHTML = `<tr><td colspan="9" class="text-center empty-state">No evidence files imported for case ${state.activeCaseId}. Click "+ Import Evidence File" above.</td></tr>`;
      return;
    }

    tbody.innerHTML = list.map(ev => `
      <tr>
        <td><code>${escapeHtml(ev.evidence_id)}</code></td>
        <td><code>${escapeHtml(ev.case_id)}</code></td>
        <td><b>${escapeHtml(ev.original_filename)}</b></td>
        <td>${escapeHtml(ev.mime_type || "text")}</td>
        <td>${escapeHtml(ev.file_size_bytes)}</td>
        <td><code class="hash-code">${escapeHtml(ev.sha256_hash)}</code></td>
        <td>${escapeHtml((ev.ingested_at || "").substring(0, 19))}</td>
        <td><span class="badge ${ev.parse_status === 'SUCCESS' ? 'badge-normal' : 'badge-suspicious'}">${escapeHtml(ev.parse_status)}</span></td>
        <td><b>${escapeHtml(ev.event_count)}</b></td>
        <td>
          <button class="btn btn-xs btn-outline" id="btn-verify-${escapeHtml(ev.evidence_id)}" onclick="verifyEvidenceFile('${escapeHtml(ev.case_id)}', '${escapeHtml(ev.evidence_id)}')">🔍 Verify Hash</button>
        </td>
      </tr>
    `).join("");
  } catch (err) {
    console.error(err);
  }
}

// Verify Evidence Integrity
async function verifyEvidenceFile(caseId, evidenceId) {
  const btn = document.getElementById(`btn-verify-${evidenceId}`);
  if (btn) {
    btn.disabled = true;
    btn.innerText = "Verifying...";
  }
  try {
    const res = await secureFetch(
      `/api/cases/${caseId}/evidence/${evidenceId}/verify`,
      {
        method: "POST",
        cache: "no-store"
      }
    );
    const data = await res.json();
    if (res.ok && data.verified) {
      alert(`✅ Evidence Integrity Verified!\nFile: ${data.filename}\nRecorded SHA-256: ${data.recorded_sha256}\nComputed SHA-256: ${data.computed_sha256}\nResult: ${data.message}`);
      if (btn) {
        btn.className = "btn btn-xs btn-success";
        btn.innerText = "✅ Hash Verified";
      }
    } else {
      alert(`❌ Evidence Verification Error: ${data.message || 'Hash mismatch!'}`);
      if (btn) {
        btn.className = "btn btn-xs btn-danger";
        btn.innerText = "❌ Mismatch";
      }
    }
  } catch (err) {
    alert(`Verification request failed: ${err.message}`);
    if (btn) {
      btn.disabled = false;
      btn.innerText = "🔍 Verify Hash";
    }
  }
}

// Load Case Events
async function loadCaseEvents() {
  if (!state.activeCaseId) return;
  const tbody = document.getElementById("tbody-events-list");
  if (!tbody) return;

  const search = document.getElementById("filter-search").value.trim();
  const label = document.getElementById("filter-label").value;
  const rulesOnly = document.getElementById("filter-rules-only").checked;

  const params = new URLSearchParams({
    page: state.currentPage,
    per_page: state.perPage,
    search: search,
    label: label,
    rule_only: rulesOnly ? "true" : "false",
  });

  try {
    const res = await secureFetch(`/api/cases/${state.activeCaseId}/events?${params}`);
    const data = await res.json();
    if (!res.ok) return;

    state.totalEvents = data.total_events;
    document.getElementById("pagination-info").innerText = `Showing ${data.events.length} of ${data.total_events} events (Page ${data.page} of ${data.total_pages || 1})`;
    document.getElementById("current-page-num").innerText = data.page;
    document.getElementById("btn-prev-page").disabled = (data.page <= 1);
    document.getElementById("btn-next-page").disabled = (data.page >= data.total_pages);

    if (!data.events.length) {
      tbody.innerHTML = `<tr><td colspan="10" class="text-center empty-state">No log events match current query or no evidence has been parsed.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.events.map(ev => {
      let predBadge = `<span class="badge badge-outline">PENDING</span>`;
      if (ev.predicted_label === "suspicious") {
        predBadge = `<span class="badge badge-suspicious">SUSPICIOUS</span>`;
      } else if (ev.predicted_label === "normal") {
        predBadge = `<span class="badge badge-normal">NORMAL</span>`;
      }

      let ruleBadges = "-";
      if (ev.rule_matches && ev.rule_matches.length > 0) {
        ruleBadges = ev.rule_matches.map(r => `<span class="badge badge-rule" title="${r.description}">${r.technique}</span>`).join(" ");
      }

      const scoreStr = (ev.score !== null && ev.score !== undefined) ? `${(ev.score * 100).toFixed(1)}%` : "-";
      const rawSafe = (ev.raw_message || "").replace(/</g, "&lt;").replace(/>/g, "&gt;");

      return `
        <tr>
          <td><code>${escapeHtml(ev.event_id)}</code></td>
          <td>${escapeHtml((ev.timestamp_utc || "N/A").substring(0, 19))}</td>
          <td>${escapeHtml(ev.host || "-")}</td>
          <td>${escapeHtml(ev.user || "-")}</td>
          <td>${escapeHtml(ev.event_code || "-")}</td>
          <td style="max-width: 320px; word-break: break-all;"><code>${escapeHtml(ev.raw_message || "")}</code></td>
          <td>${predBadge}</td>
          <td><b>${scoreStr}</b></td>
          <td>${ruleBadges}</td>
          <td>
            <button class="btn btn-xs btn-outline" onclick="explainEvent('${escapeHtml(ev.event_id)}')">💡 SHAP</button>
            <button class="btn btn-xs btn-secondary" onclick="openNoteModal('${escapeHtml(ev.event_id)}')">📝 Note</button>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error(err);
  }
}

function handleSearchKey(event) {
  if (event.key === "Enter") {
    state.currentPage = 1;
    loadCaseEvents();
  }
}

function changePage(delta) {
  state.currentPage += delta;
  loadCaseEvents();
}

// Export Events CSV
function exportEventsCSV() {
  if (!state.activeCaseId) {
    alert("Select an active case first.");
    return;
  }
  window.location.href = `/api/cases/${state.activeCaseId}/events/export`;
}

// Run Case Analysis
async function runCaseAnalysis() {
  if (!state.activeCaseId) {
    alert("Select an active case first.");
    return;
  }
  const btn = document.getElementById("btn-run-analysis");
  if (btn) {
    btn.disabled = true;
    btn.innerText = "Analyzing Logs...";
  }

  try {
    const res = await secureFetch(`/api/cases/${state.activeCaseId}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ examiner: state.activeExaminer }),
    });
    const data = await res.json();
    if (res.ok) {
      alert(`Analysis Complete!\n${data.message}`);
      loadCaseEvents();
      loadCaseTimeline();
      loadCaseAudit();
    } else {
      alert(`Analysis Notice: ${data.message}`);
    }
  } catch (err) {
    alert(`Analysis error: ${err.message}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerText = "⚡ Run Detection Model";
    }
  }
}

// SHAP Explanation Modal
async function explainEvent(eventId) {
  const modal = document.getElementById("modal-shap-explanation");
  const body = document.getElementById("shap-modal-body");
  body.innerHTML = "<p>Computing TreeExplainer SHAP attributions...</p>";
  showModal("modal-shap-explanation");

  try {
    const res = await secureFetch(`/api/events/${eventId}/explanation`);
    const data = await res.json();
    if (!res.ok) {
      body.innerHTML = `<div class="alert-box alert-warning">${data.message || "Could not retrieve explanation."}</div>`;
      return;
    }

    const exp = data.explanation || {};
    const tokens = exp.tokens || [];
    const maxVal = Math.max(...tokens.map(t => Math.abs(t.contribution)), 0.001);

    const barsHtml = tokens.map(t => {
      const isPos = t.contribution > 0;
      const widthPct = Math.min(100, Math.round((Math.abs(t.contribution) / maxVal) * 100));
      return `
        <div class="shap-token-bar">
          <span class="shap-token-name" title="${t.feature}"><b>${t.feature}</b></span>
          <div class="shap-bar-track">
            <div class="shap-bar-fill ${isPos ? 'shap-fill-pos' : 'shap-fill-neg'}" style="width: ${widthPct}%;"></div>
          </div>
          <span class="shap-val-text ${isPos ? 'text-rose' : 'text-emerald'}">${isPos ? '+' : ''}${t.contribution}</span>
        </div>
      `;
    }).join("");

    body.innerHTML = `
      <div class="alert-box alert-info">
        <b>${data.caveat}</b>
      </div>
      <div style="margin-bottom: 12px;">
        <p><b>Event ID:</b> <code>${data.event_id}</code> | <b>Classification:</b> <span class="badge ${data.predicted_label === 'suspicious' ? 'badge-suspicious' : 'badge-normal'}">${data.predicted_label || 'NORMAL'}</span> | <b>Score:</b> ${data.score !== null ? (data.score * 100).toFixed(1) + '%' : 'N/A'}</p>
        <p style="margin-top: 6px;"><b>Analyzed Text:</b> <code style="word-break: break-all;">${(data.normalized_text || data.raw_message || '').replace(/</g, "&lt;")}</code></p>
      </div>
      <h4 style="margin: 14px 0 8px 0;">Token Attribution Magnitudes (Top Features):</h4>
      <div style="background: var(--bg-primary); border: 1px solid var(--border-color); padding: 12px; border-radius: 6px; margin-bottom: 12px;">
        ${barsHtml || '<p class="empty-state">No prominent vocabulary tokens active for this event.</p>'}
      </div>
      <div class="alert-box alert-warning">
        <b>Investigative Rationale:</b> ${exp.rationale || 'N/A'}
      </div>
    `;
  } catch (err) {
    body.innerHTML = `<div class="alert-box alert-warning">Failed to load SHAP explanation: ${err.message}</div>`;
  }
}

// Open Note Modal
function openNoteModal(eventId) {
  document.getElementById("note-event-id").value = eventId;
  document.getElementById("note-display-event-id").value = eventId;
  document.getElementById("note-author").value = state.activeExaminer;
  document.getElementById("note-text").value = "";
  showModal("modal-add-note");
}

async function handleSaveNote(event) {
  event.preventDefault();
  if (!state.activeCaseId) return;

  const eventId = document.getElementById("note-event-id").value;
  const author = document.getElementById("note-author").value.trim();
  const noteText = document.getElementById("note-text").value.trim();

  try {
    const res = await secureFetch(`/api/cases/${state.activeCaseId}/notes`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        event_id: eventId,
        author: author,
        note_text: noteText,
      }),
    });
    if (res.ok) {
      alert("Investigator note saved.");
      closeModal("modal-add-note");
      loadCaseTimeline();
    } else {
      alert("Error saving note.");
    }
  } catch (err) {
    alert(`Failed: ${err.message}`);
  }
}

// Load Case Timeline
async function loadCaseTimeline() {
  if (!state.activeCaseId) return;
  const win = document.getElementById("timeline-window").value;
  const containerGaps = document.getElementById("container-log-gaps");
  const containerStream = document.getElementById("container-timeline-stream");

  try {
    const res = await secureFetch(`/api/cases/${state.activeCaseId}/timeline?window_minutes=${win}`);
    const data = await res.json();
    if (!res.ok) return;

    const t = data.timeline || {};
    const gaps = t.log_gaps || [];
    const flagged = t.contextual_groups || [];

    // Render Gaps
    if (gaps.length > 0) {
      containerGaps.innerHTML = `
        <div class="alert-box alert-warning">
          <h4>⚠️ ${gaps.length} Silent Logging Gap(s) Detected</h4>
          <ul style="margin-left: 20px; margin-top: 6px;">
            ${gaps.map(g => `<li><b>${g.host}:</b> Silent period of ${g.gap_duration_minutes} minutes between ${g.start_time.substring(11, 19)} and ${g.end_time.substring(11, 19)}.</li>`).join("")}
          </ul>
        </div>
      `;
    } else {
      containerGaps.innerHTML = `<div class="alert-box alert-success">✅ No uncharacteristic silent log gaps detected.</div>`;
    }

    // Render Flagged Event Groups
    if (!flagged.length) {
      containerStream.innerHTML = `<div class="empty-state">No flagged anti-forensic events to reconstruct context for. Run detection or import logs first.</div>`;
      return;
    }

    containerStream.innerHTML = flagged.map(f => {
      const nearbyHtml = f.nearby_events.map(n => `
        <li style="margin-bottom: 4px; font-size: 11px;">
          <span style="color: var(--text-muted);">${(n.timestamp_utc || '').substring(11, 19)}</span>
          [${n.host || '-'}] <code>${(n.raw_message || '').substring(0, 75)}...</code>
        </li>
      `).join("");

      return `
        <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-left: 4px solid var(--accent-rose); border-radius: 8px; padding: 16px; margin-bottom: 14px; box-shadow: var(--shadow-sm);">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <span><code>${f.flagged_event_id}</code> | <b>${f.timestamp_utc || 'N/A'}</b> | Host: <b>${f.host || '-'}</b> | User: <b>${f.user || '-'}</b></span>
            <span class="badge badge-suspicious">SCORE: ${(f.score * 100).toFixed(1)}%</span>
          </div>
          <div style="margin-bottom: 8px;">
            <code>${(f.raw_message || '').replace(/</g, "&lt;")}</code>
          </div>
          ${nearbyHtml ? `
            <div style="background: var(--bg-primary); border: 1px solid var(--border-color); padding: 10px 14px; border-radius: 6px; margin-top: 10px;">
              <small style="color: var(--text-muted); font-weight: 600; text-transform: uppercase;">Nearby Events Context (±${win} mins):</small>
              <ul style="margin-left: 16px; margin-top: 4px;">
                ${nearbyHtml}
              </ul>
            </div>
          ` : '<small style="color: var(--text-muted);">No other events recorded in nearby temporal window.</small>'}
        </div>
      `;
    }).join("");
  } catch (err) {
    console.error(err);
  }
}

// Generate Case Report
async function generateCaseReport() {
  if (!state.activeCaseId) {
    alert("Select an active case first.");
    return;
  }
  const btn = document.getElementById("btn-gen-report");
  if (btn) {
    btn.disabled = true;
    btn.innerText = "Building PDF...";
  }

  try {
    const res = await secureFetch(`/api/cases/${state.activeCaseId}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ examiner: state.activeExaminer }),
    });
    const data = await res.json();
    if (res.ok) {
      alert(`Report Generated!\nReport ID: ${data.report_id}\nSHA-256 Digest: ${data.sha256_hash}`);
      loadCaseAudit();
      switchTab("tab-reports");
      const tbody = document.getElementById("tbody-reports-list");

      if (tbody) {
        const emptyRow = tbody.querySelector(".empty-state");

        if (emptyRow) {
          emptyRow.closest("tr").remove();
        }

        const row = tbody.insertRow(0);

        const values = [
          data.report_id,
          data.case_id || state.activeCaseId,
          data.filename,
          data.created_at_utc || new Date().toISOString(),
          data.examiner || state.activeExaminer || "Forensic Officer",
          data.sha256_hash
        ];

        values.forEach(value => {
          const cell = row.insertCell();
          cell.textContent = value || "";
        });

        const actionCell = row.insertCell();
        const link = document.createElement("a");

        link.href = `/api/reports/${encodeURIComponent(data.report_id)}/download`;
        link.className = "btn btn-xs btn-success";
        link.textContent = "Download PDF";
        link.setAttribute("download", data.filename);

        actionCell.appendChild(link);
      }

      loadCaseAudit();
      switchTab("tab-reports");
    } else {
      alert(`Report Error: ${data.message}`);
    }
  } catch (err) {
    alert(`Failed to generate report: ${err.message}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerText = "📑 Generate PDF";
    }
  }
}

// Verify Audit Trail
async function verifyAuditChain() {
  const banner = document.getElementById(
    "audit-verification-banner"
  );

  const buttons = Array.from(
    document.querySelectorAll(
      'button[onclick="verifyAuditChain()"]'
    )
  );

  const originalTexts = buttons.map(
    btn => btn.innerText
  );

  buttons.forEach(btn => {
    btn.disabled = true;
    btn.innerText = "Verifying Audit...";
  });

  try {
    const caseId = state.activeCaseId;

    if (!caseId) {
      alert("Please select an investigation case first.");
      return;
    }

    const url =
      `/api/audit/verify?case_id=${encodeURIComponent(caseId)}`;

    const res = await secureFetch(url, {
      cache: "no-store"
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    const data = await res.json();

    if (typeof data.is_valid !== "boolean") {
      throw new Error("Invalid audit response.");
    }

    const scope = caseId;

    let message;

    if (data.is_valid) {
      message =
        "Audit Integrity Verified!\n\n" +
        "Scope: " + scope + "\n" +
        "Total audit entries: " +
        data.total_entries + "\n\n" +
        data.message;
    } else {
      message =
        "Audit Integrity Check Failed!\n\n" +
        "Scope: " + scope + "\n" +
        (data.error || data.message ||
          "Audit chain requires review.");
    }

    if (banner) {
      banner.style.display = "block";

      banner.className = data.is_valid
        ? "alert-box alert-success"
        : "alert-box alert-warning";

      banner.textContent = message;
      banner.style.whiteSpace = "pre-line";
    }

    alert(message);

  } catch (err) {
    alert("Audit verification failed:\n" + err.message);

    if (banner) {
      banner.style.display = "block";
      banner.className = "alert-box alert-warning";
      banner.textContent =
        "Audit verification failed: " + err.message;
    }

  } finally {
    buttons.forEach((btn, index) => {
      btn.disabled = false;
      btn.innerText = originalTexts[index];
    });
  }
}
// Load Case Audit Log
async function loadCaseAudit() {
  if (!state.activeCaseId) return;
  const tbody = document.getElementById("tbody-audit-list");
  if (!tbody) return;

  try {
    const res = await secureFetch(`/api/cases/${state.activeCaseId}`);
    const data = await res.json();
    if (!res.ok) return;

    const entries = data.audit_trail || [];
    if (!entries.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center empty-state">No audit ledger records for case ${state.activeCaseId}.</td></tr>`;
      return;
    }

    tbody.innerHTML = entries.map(a => `
      <tr>
        <td><code>#${escapeHtml(a.audit_id)}</code></td>
        <td><span class="badge badge-normal">${escapeHtml(a.action)}</span></td>
        <td>${escapeHtml(a.actor || "Forensic Examiner")}</td>
        <td><code>${escapeHtml(a.evidence_id || "-")}</code></td>
        <td>${escapeHtml((a.timestamp_utc || "").substring(0, 19))}</td>
        <td><code class="hash-code">${escapeHtml((a.previous_entry_hash || "").substring(0, 16))}...</code></td>
        <td><code class="hash-code">${escapeHtml((a.entry_hash || "").substring(0, 16))}...</code></td>
      </tr>
    `).join("");
  } catch (e) {
    console.error(e);
  }
}

// -------------------------------------------------------------
// Real-Time Monitoring & Incremental Replay (Section 18.1)
// -------------------------------------------------------------
let livePollTimer = null;

function handleLiveModeChange() {
  const mode = document.getElementById("live-mode-select").value;
  const targetGroup = document.getElementById("group-target-dir");
  if (targetGroup) {
    targetGroup.style.display = (mode === "DIRECTORY") ? "block" : "none";
  }
}

async function startLiveIngestion() {
  const mode = document.getElementById("live-mode-select").value;
  const targetCase = document.getElementById("live-target-case").value.trim() || state.activeCaseId || "CASE-LIVE-STREAM";
  const interval = parseFloat(document.getElementById("live-interval-select").value || 1.0);
  const targetDir = document.getElementById("live-target-dir").value.trim();

  try {
    const res = await secureFetch("/api/live/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mode: mode,
        case_id: targetCase,
        poll_interval: interval,
        target_dir: targetDir,
      })
    });
    const data = await res.json();
    if (res.ok) {
      updateLiveControls("RUNNING");
      pollLiveStatus();
      if (!livePollTimer) {
        livePollTimer = setInterval(pollLiveStatus, 1500);
      }
    } else {
      alert(`Live Monitor Error: ${data.message}`);
    }
  } catch (err) {
    alert(`Failed to start live monitor: ${err.message}`);
  }
}

async function pauseLiveIngestion() {
  try {
    const res = await secureFetch("/api/live/pause", { method: "POST" });
    const data = await res.json();
    if (res.ok) {
      updateLiveControls("PAUSED");
      pollLiveStatus();
    }
  } catch (e) {
    console.error(e);
  }
}

async function resumeLiveIngestion() {
  try {
    const res = await secureFetch("/api/live/resume", { method: "POST" });
    const data = await res.json();
    if (res.ok) {
      updateLiveControls("RUNNING");
      pollLiveStatus();
    }
  } catch (e) {
    console.error(e);
  }
}

async function stopLiveIngestion() {
  try {
    const res = await secureFetch("/api/live/stop", { method: "POST" });
    const data = await res.json();
    if (res.ok) {
      updateLiveControls("STOPPED");
      pollLiveStatus();
      if (livePollTimer) {
        clearInterval(livePollTimer);
        livePollTimer = null;
      }
    }
  } catch (e) {
    console.error(e);
  }
}

function updateLiveControls(status) {
  const btnStart = document.getElementById("btn-live-start");
  const btnPause = document.getElementById("btn-live-pause");
  const btnResume = document.getElementById("btn-live-resume");
  const btnStop = document.getElementById("btn-live-stop");
  const dot = document.getElementById("live-indicator-dot");
  const statusText = document.getElementById("live-status-text");

  if (!btnStart) return;

  if (status === "RUNNING") {
    btnStart.disabled = true;
    btnPause.disabled = false;
    btnResume.disabled = true;
    btnStop.disabled = false;
    if (dot) dot.className = "pulse-indicator";
    if (statusText) {
      statusText.innerText = "STREAMING ACTIVE";
      statusText.className = "status-pill pill-evaluated";
    }
  } else if (status === "PAUSED") {
    btnStart.disabled = true;
    btnPause.disabled = true;
    btnResume.disabled = false;
    btnStop.disabled = false;
    if (dot) dot.className = "pulse-indicator pulse-paused";
    if (statusText) {
      statusText.innerText = "PAUSED";
      statusText.className = "status-pill pill-pending";
    }
  } else {
    btnStart.disabled = false;
    btnPause.disabled = true;
    btnResume.disabled = true;
    btnStop.disabled = true;
    if (dot) dot.className = "pulse-indicator pulse-stopped";
    if (statusText) {
      statusText.innerText = "STOPPED";
      statusText.className = "status-pill pill-pending";
    }
  }
}

async function pollLiveStatus() {
  if (livePollTimer) {
    clearInterval(livePollTimer);
    livePollTimer = null;
  }
}

// -------------------------------------------------------------
// Datasets Feasibility Audit Loader (Section 18.2)
// -------------------------------------------------------------
async function loadDatasetsAudit(manual = false) {
  const tbody = document.getElementById("tbody-datasets-matrix");
  const btn = document.getElementById("btn-feasibility-audit");

  if (!tbody) return;

  const originalText = btn ? btn.innerText : "";

  if (manual && btn) {
    btn.disabled = true;
    btn.innerText = "Running Feasibility Audit...";
  }

  try {
    const res = await secureFetch("/api/datasets/status", {
      cache: "no-store"
    });

    if (!res.ok) {
      throw new Error(`Audit failed: HTTP ${res.status}`);
    }

    const data = await res.json();

    if (!Array.isArray(data.datasets)) {
      throw new Error("Invalid dataset audit response.");
    }

    const list = data.datasets;
    tbody.replaceChildren();

    for (const d of list) {
      const row = tbody.insertRow();

      const nameCell = row.insertCell();
      const name = document.createElement("b");
      name.textContent = d.name || "Unknown";

      const code = document.createElement("code");
      code.textContent = d.dataset_id || "";

      nameCell.append(name, document.createElement("br"), code);

      const values = [
        d.role,
        d.format,
        d.license_terms,
        d.label_availability,
        d.compatibility_verdict
      ];

      values.forEach(value => {
        const cell = row.insertCell();
        cell.textContent = value || "N/A";
      });

      const statusCell = row.insertCell();
      const badge = document.createElement("span");

      const status = d.feasibility_status || "UNKNOWN";

      badge.className = "badge " +
        (status === "SUPPORTED_AND_TESTED"
          ? "badge-normal"
          : "badge-pending");

      badge.textContent = status;
      statusCell.appendChild(badge);
    }

    if (manual) {
      alert(
        "Feasibility Audit Completed!\n\n" +
        "Dataset entries checked: " + list.length + "\n" +
        "Dataset status table updated successfully.\n\n" +
        "Review individual statuses and limitations."
      );
    }

  } catch (err) {
    console.error("Dataset audit failed:", err);

    if (manual) {
      alert("Feasibility Audit Failed:\n" + err.message);
    }

  } finally {
    if (manual && btn) {
      btn.disabled = false;
      btn.innerText = originalText;
    }
  }
}
// Train Test Model on Fixtures
async function trainTestModel() {
  if (!confirm("Train TF-IDF + Random Forest baseline on verified software fixtures?")) return;
  try {
    const res = await secureFetch("/api/models/train", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source: "fixtures" })
    });
    const data = await res.json();
    if (res.ok) {
      alert(`Model Pipeline Fitted & Saved!\nVersion: ${data.metadata.model_version}\nF1 Score on Test Split: ${data.metadata.metrics.f1_score}\nAccuracy: ${data.metadata.metrics.accuracy}`);
      window.location.reload();
    } else {
      alert(`Training notice: ${data.message}`);
    }
  } catch (e) {
    alert(`Training failed: ${e.message}`);
  }
}


async function loadEvaluationDatasets() {
    const tbody = document.getElementById("tbody-evaluation-datasets");
    if (!tbody) return;

    try {
        const res = await secureFetch("/api/datasets/status");
        if (!res.ok) {
            throw new Error("Dataset status unavailable");
        }

        const data = await res.json();
        const list = data.datasets || [];

        tbody.replaceChildren();

        for (const d of list) {
            const row = document.createElement("tr");

            const values = [
                d.dataset_id,
                d.name,
                d.feasibility_status,
                d.format,
                d.label_availability,
                d.role
            ];

            values.forEach((value, index) => {
                const td = document.createElement("td");

                if (index === 2) {
                    const badge = document.createElement("span");
                    badge.className = "badge " +
                        (value === "SUPPORTED_AND_TESTED"
                            ? "badge-normal"
                            : "badge-pending");

                    badge.textContent = value || "Unknown";
                    td.appendChild(badge);
                } else {
                    td.textContent = value || "N/A";
                }

                row.appendChild(td);
            });

            tbody.appendChild(row);
        }

    } catch (err) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center empty-state">
                    Unable to load dataset status.
                </td>
            </tr>`;
        console.error(err);
    }
}

async function loadResearchResults() {

    const metrics = document.getElementById(
        "silrad-metrics"
    );

    const details = document.getElementById(
        "silrad-details"
    );

    const ablation = document.getElementById(
        "silrad-ablation"
    );

    const table = document.getElementById(
        "external-research-table"
    );

    const reference = document.getElementById(
        "external-reference"
    );

    const graphs = document.getElementById(
        "silrad-graphs"
    );

    if (!metrics) return;

    const number = value =>
        value == null
            ? "N/A"
            : Number(value).toLocaleString();

    const percent = value =>
        value == null
            ? "N/A"
            : (Number(value) * 100).toFixed(2) + "%";

    function addMetric(container, label, value) {

        const card = document.createElement("div");
        card.className = "metric-card";

        const name = document.createElement("div");
        name.className = "metric-label";
        name.textContent = label;

        const val = document.createElement("div");
        val.className = "metric-value";
        val.textContent = value;

        card.append(name, val);
        container.appendChild(card);
    }

    function showTableMessage(message) {

        table.replaceChildren();

        const tr = document.createElement("tr");
        const td = document.createElement("td");

        td.colSpan = 8;
        td.textContent = message;

        tr.appendChild(td);
        table.appendChild(tr);
    }

    try {

        const response = await secureFetch(
            "/api/research/results",
            {cache: "no-store"}
        );

        if (!response.ok) {
            throw new Error(
                "Research results unavailable"
            );
        }

        const data = await response.json();

        metrics.replaceChildren();
        details.replaceChildren();
        ablation.replaceChildren();
        reference.replaceChildren();
        graphs.replaceChildren();

        // SILRAD measured metrics

        const s = data.silrad;

        if (s) {

            addMetric(metrics, "Accuracy",
                percent(s.accuracy));

            addMetric(metrics, "Precision",
                percent(s.precision));

            addMetric(metrics, "Recall",
                percent(s.recall));

            addMetric(metrics, "F1-Score",
                percent(s.f1_score));

            addMetric(metrics, "False Positive Rate",
                percent(s.false_positive_rate));

            addMetric(metrics, "Test Records",
                number(s.testing_records));

            details.textContent =
                "Model: " + s.model_version +
                " | Training records: " +
                number(s.training_records) +
                " | Evaluation: " +
                s.evaluation_status;

        } else {
            metrics.textContent =
                "SILRAD evaluation results unavailable.";
        }

        // Ablation results

        const a = data.ablation;

        if (a) {

            const grid = document.createElement("div");
            grid.className = "metrics-grid";

            addMetric(grid, "Remaining Features",
                number(a.remaining_features));

            addMetric(grid, "Accuracy",
                percent(a.accuracy));

            addMetric(grid, "Precision",
                percent(a.precision));

            addMetric(grid, "Recall",
                percent(a.recall));

            addMetric(grid, "F1-Score",
                percent(a.f1_score));

            addMetric(grid, "Remaining Overlap",
                number(a.remaining_overlap));

            ablation.appendChild(grid);

            const note = document.createElement("p");

            note.textContent =
                "Removed features: " +
                a.removed_features.join(", ") +
                " | Test records: " +
                number(a.testing_records) +
                " | Conflicting groups removed: " +
                number(a.conflicting_groups_removed);

            ablation.appendChild(note);

        } else {
            ablation.textContent =
                "Ablation results unavailable.";
        }

        // External hybrid analysis

        if (data.external &&
            Array.isArray(data.external.datasets)) {

            table.replaceChildren();

            for (const d of data.external.datasets) {

                const c = d.combined_counts || {};
                const sh = d.shap_status_counts || {};

                const values = [
                    d.dataset,
                    number(d.parsed_records),
                    number(c.ML_ONLY_CANDIDATE || 0),
                    number(c.ML_AND_RULE_CANDIDATE || 0),
                    number(c.RULE_ONLY_CANDIDATE || 0),
                    number(c.NO_INDICATOR_UNVERIFIED || 0),
                    number(c.INSUFFICIENT_VOCABULARY || 0),
                    number(sh.SUCCESS || 0)
                ];

                const tr = document.createElement("tr");

                for (const value of values) {

                    const td = document.createElement("td");
                    td.textContent = value;
                    tr.appendChild(td);
                }

                table.appendChild(tr);

                for (const r of d.reference_records || []) {

                    const p = document.createElement("p");

                    p.textContent =
                        "Official HTB reference: CSV row " +
                        r.original_row +
                        " | Event ID " + r.event_code +
                        " | Prediction: " +
                        r.model_prediction +
                        " | Suspicious score: " +
                        percent(r.suspicious_score) +
                        " | Rule: " + r.rule_ids +
                        " | SHAP: " + r.shap_status;

                    reference.appendChild(p);
                }
            }

        } else {
            showTableMessage(
                "External analysis results unavailable."
            );
        }

        // Research graphs

        const files = [
            ["silrad_confusion_matrix.png",
             "Confusion Matrix"],

            ["silrad_performance.png",
             "Performance Metrics"],

            ["silrad_shap_importance.png",
             "SHAP Feature Importance"],

            ["silrad_shap_summary.png",
             "SHAP Summary"]
        ];

        for (const [file, title] of files) {

            const figure = document.createElement("div");

            const heading = document.createElement("h4");
            heading.textContent = title;

            const image = document.createElement("img");

            image.src = "/api/research/graphs/" + file;
            image.alt = title;
            image.loading = "lazy";
            image.style.width = "100%";
            image.style.borderRadius = "8px";

            image.onerror = function() {

                const message =
                    document.createElement("p");

                message.textContent =
                    "Graph unavailable: " + title;

                image.replaceWith(message);
            };

            figure.append(heading, image);
            graphs.appendChild(figure);
        }

    } catch (error) {

        metrics.textContent =
            "Unable to load research results.";

        details.replaceChildren();
        ablation.textContent = "Results unavailable.";
        reference.replaceChildren();
        graphs.replaceChildren();

        showTableMessage(
            "Unable to load external results."
        );

        console.error(error);
    }
}



function handleFixtureSelectChange() {
  const sel = document.getElementById("demo-fixture-select");
  const descEl = document.getElementById("fixture-desc");
  const shaEl = document.getElementById("fixture-sha");
  if (!sel || !descEl || !shaEl) return;

  const fixtures = { public_demo_logs: { desc: "Synthetic educational records demonstrating normal authentication and forensic audit alerts.", sha: "6dac4e828686bebe6d85ddf6161384630492f1c17789dea72f7022b2619c0cf0" } };

  const chosen = fixtures[sel.value];
  if (chosen) {
    descEl.innerText = chosen.desc;
    shaEl.innerText = chosen.sha;
  }
}

// Restore active case from sessionStorage on DOMContentLoaded
window.addEventListener("DOMContentLoaded", () => {
  try {
    const saved = sessionStorage.getItem("fs_active_case");
    if (saved) {
      const parsed = JSON.parse(saved);
      if (parsed && parsed.caseId) {
        selectCase(parsed.caseId, parsed.title, parsed.examiner);
      }
    }
  } catch (e) {}
});
