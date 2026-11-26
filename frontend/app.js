/* RAKSHA Dynamic Dataset-Driven Command Center (Offline, Zero External Dependencies) */
(function () {
  "use strict";

  const PAGE_TITLES = {
    overview: "Overview",
    ingestion: "Datasets & Inspection",
    processing: "Processing Centre",
    pipeline: "Security Pipeline",
    analytics: "Privacy Analytics",
    clinical: "Clinical Preservation",
    linkage: "Patient Linkage",
    audit: "File Audit",
    reports: "Reports & Exports",
    settings: "System Settings",
  };

  const state = {
    activePage: "overview",
    datasets: [],
    activeDatasetId: "practice",
    inspection: null,
    inspectPage: 1,
    runs: [],
    activeRunId: null,
    pollTimer: null,
    overview: null,
    filesResp: { files: [], total: 0, page: 1, page_size: 50, formats: [] },
    selectedFileDetail: null,
    linkageResp: { summary: {}, clusters: [], records: [], total: 0, page: 1, page_size: 50, source_files: [], formats: [] },
    uploadQueue: [],
    uploadName: "",
    uploadBusy: false,
    auditFilter: "all",
    auditFormat: "all",
    auditSort: "index",
    auditSearch: "",
    auditPage: 1,
    linkageFilter: "all",
    linkageFile: "all",
    linkageFormat: "all",
    linkageSearch: "",
    linkagePage: 1,
  };

  function esc(val) {
    return String(val ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function fmtNum(n) {
    if (n === null || n === undefined) return "Not yet evaluated";
    return Number(n).toLocaleString("en-US");
  }

  function fmtBytes(bytes) {
    if (bytes === null || bytes === undefined) return "—";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  function detectFormat(filename) {
    const ext = (filename.split(".").pop() || "").toLowerCase();
    if (ext === "csv") return "CSV";
    if (ext === "tsv") return "TSV";
    if (ext === "json") return "JSON / FHIR R4";
    if (ext === "txt") return "TXT";
    return ext ? ext.toUpperCase() : "UNKNOWN";
  }

  async function apiJson(url, opts) {
    const res = await fetch(url, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.error || `Request failed (${res.status})`);
    }
    return data;
  }

  function setError(msg) {
    const el = document.getElementById("error-banner");
    el.textContent = msg || "";
    el.style.display = msg ? "block" : "none";
  }

  function setLoading(show) {
    document.getElementById("loading-banner").style.display = show ? "block" : "none";
  }

  function navigate(page) {
    if (!PAGE_TITLES[page]) return;
    state.activePage = page;
    document.querySelectorAll(".nav-item").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.page === page);
    });
    document.querySelectorAll(".page").forEach((sec) => {
      sec.classList.toggle("active", sec.id === `page-${page}`);
    });
    document.getElementById("crumb-current").textContent = PAGE_TITLES[page];
    document.getElementById("sidebar").classList.remove("open");
    renderActivePage();
  }

  async function loadAllData() {
    setError("");
    setLoading(true);
    try {
      const [dsRes, runsRes, ovRes] = await Promise.all([
        apiJson("/api/datasets"),
        apiJson("/api/runs"),
        apiJson("/api/overview"),
      ]);
      state.datasets = dsRes.datasets || [];
      state.activeDatasetId = dsRes.active_dataset_id || "practice";
      state.runs = runsRes.runs || [];
      state.activeRunId = runsRes.active_run_id || null;
      state.overview = ovRes;

      const [inspRes, filesRes, linkRes] = await Promise.all([
        apiJson(`/api/datasets/inspect?dataset_id=${encodeURIComponent(state.activeDatasetId)}&page=${state.inspectPage}&page_size=50`),
        apiJson(`/api/files?status=${encodeURIComponent(state.auditFilter)}&format=${encodeURIComponent(state.auditFormat)}&sort=${encodeURIComponent(state.auditSort)}&q=${encodeURIComponent(state.auditSearch)}&page=${state.auditPage}&page_size=50`),
        apiJson(`/api/linkage?status=${encodeURIComponent(state.linkageFilter)}&file=${encodeURIComponent(state.linkageFile)}&format=${encodeURIComponent(state.linkageFormat)}&q=${encodeURIComponent(state.linkageSearch)}&page=${state.linkagePage}&page_size=50`),
      ]);
      state.inspection = inspRes;
      state.filesResp = filesRes;
      state.linkageResp = linkRes;

      updateChrome();
      managePolling();
      renderActivePage();
    } catch (err) {
      setError(`Backend connection issue: ${err.message}. Click Refresh to retry.`);
    } finally {
      setLoading(false);
    }
  }

  function managePolling() {
    const activeRun = state.runs.find((r) => r.run_id === state.activeRunId);
    if (activeRun && activeRun.status === "processing") {
      if (!state.pollTimer) {
        state.pollTimer = setInterval(async () => {
          try {
            const st = await apiJson(`/api/runs/status?run_id=${encodeURIComponent(state.activeRunId)}`);
            const idx = state.runs.findIndex((r) => r.run_id === st.run_id);
            if (idx >= 0) state.runs[idx] = st;
            if (st.status !== "processing") {
              clearInterval(state.pollTimer);
              state.pollTimer = null;
              await loadAllData();
            } else if (state.activePage === "processing") {
              renderProcessing();
            }
          } catch (_) {
            clearInterval(state.pollTimer);
            state.pollTimer = null;
          }
        }, 900);
      }
    } else if (state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  }

  function updateChrome() {
    const ov = state.overview || {};
    const c = ov.counts || {};
    document.getElementById("badge-entities").textContent = ov.has_output ? fmtNum(c.identifiers_detected || 0) : "—";
    document.getElementById("badge-files").textContent = ov.has_output ? fmtNum(c.files_total || 0) : "—";

    const activeDs = state.datasets.find((d) => d.id === state.activeDatasetId);
    document.getElementById("sidebar-mode-pill").textContent = activeDs ? activeDs.name : state.activeDatasetId;

    const dsSel = document.getElementById("topbar-dataset-select");
    dsSel.innerHTML = state.datasets.map((d) => `<option value="${esc(d.id)}" ${d.id === state.activeDatasetId ? "selected" : ""}>${esc(d.name)}</option>`).join("");

    const runSel = document.getElementById("topbar-run-select");
    const matchingRuns = state.runs.filter((r) => r.dataset_id === state.activeDatasetId);
    runSel.innerHTML = matchingRuns.length
      ? matchingRuns.map((r) => `<option value="${esc(r.run_id)}" ${r.run_id === state.activeRunId ? "selected" : ""}>${esc(r.run_id)} (${esc(r.status)})</option>`).join("")
      : `<option value="">No runs yet</option>`;

    const runState = document.getElementById("topbar-run-state");
    const activeRun = state.runs.find((r) => r.run_id === state.activeRunId);
    if (activeRun && activeRun.status === "processing") {
      runState.textContent = "PROCESSING";
      runState.className = "pill pill-warn";
    } else if (ov.has_output && ov.contract && ov.contract.ok) {
      runState.textContent = "CONTRACT OK";
      runState.className = "pill pill-ok";
    } else if (activeRun && activeRun.status === "failed") {
      runState.textContent = "FAILED";
      runState.className = "pill pill-danger";
    } else {
      runState.textContent = "READY";
      runState.className = "pill";
    }
  }

  function renderActivePage() {
    switch (state.activePage) {
      case "overview": return renderOverview();
      case "ingestion": return renderIngestion();
      case "processing": return renderProcessing();
      case "pipeline": return renderPipeline();
      case "analytics": return renderAnalytics();
      case "clinical": return renderClinical();
      case "linkage": return renderLinkage();
      case "audit": return renderAudit();
      case "reports": return renderReports();
      case "settings": return renderSettings();
    }
  }

  /* ------------------------------------------------------------------ */
  /* PAGE 1: OVERVIEW (12 Dynamic Cards + 3 Layers + Chart + Audit)     */
  /* ------------------------------------------------------------------ */
  function renderOverview() {
    const el = document.getElementById("page-overview");
    const ov = state.overview || {};
    const dsName = ov.active_dataset?.name || "Selected Dataset";

    if (!ov.has_output) {
      el.innerHTML = `
        <div class="page-header">
          <div>
            <h1 class="page-title">Overview</h1>
            <p class="page-sub">Active dataset: <strong>${esc(dsName)}</strong> • No completed run yet</p>
          </div>
          <button class="btn btn-primary" data-nav="ingestion">Inspect &amp; Process Dataset →</button>
        </div>
        <div class="card">
          <div class="kpi-title">Dataset Ready for Local Firewall Execution</div>
          <p class="page-sub" style="margin:8px 0 14px;">
            Metrics are never retained from previous datasets. Inspect the dataset or start a new run in the Processing Centre.
          </p>
          <div style="display:flex;gap:10px;">
            <button class="btn btn-primary" id="btn-ov-start">Start Processing Now</button>
            <button class="btn" data-nav="ingestion">Open Dataset Inspection</button>
          </div>
        </div>
      `;
      el.querySelectorAll("[data-nav]").forEach((n) => n.addEventListener("click", () => navigate(n.dataset.nav)));
      const sbtn = document.getElementById("btn-ov-start");
      if (sbtn) sbtn.addEventListener("click", startRunForActiveDataset);
      return;
    }

    const c = ov.counts || {};
    const a = ov.assurance || {};
    const verified = Boolean(a.verified);
    const piiRemaining = verified ? `${a.pii_leaked} / ${a.pii_total} (${a.leakage_pct}%)` : "Not yet evaluated";
    const medPres = verified ? `${a.medical_pct}% (${a.medical_kept}/${a.medical_total})` : "Not yet evaluated";
    const rssVal = ov.resources && ov.resources.peak_rss_mb > 0 ? `${ov.resources.peak_rss_mb} MB` : "Not yet evaluated";

    const entEntries = Object.entries(ov.entities || {}).sort((x, y) => y[1] - x[1]).slice(0, 8);
    const maxEnt = Math.max(1, ...entEntries.map((x) => x[1]));
    const recentFiles = (state.filesResp.files || []).slice(0, 6);

    el.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">Overview</h1>
          <p class="page-sub">Dataset: <strong>${esc(dsName)}</strong> • Run: <span class="mono">${esc(ov.active_run?.run_id || "")}</span></p>
        </div>
        <div class="topbar-right">
          <span class="pill ${ov.contract?.ok ? "pill-ok" : "pill-warn"}">${esc(ov.contract?.status || "UNKNOWN")}</span>
          <span class="pill">Elapsed: ${esc(ov.timing?.seconds ?? 0)}s</span>
        </div>
      </div>

      <div class="kpi-grid-3">
        <div class="kpi-card kpi-card-hero">
          <div class="kpi-top">
            <div><div class="kpi-title">Medical Preservation</div><div class="kpi-sub">Sanitized: ${fmtNum(c.files_sanitized)} / ${fmtNum(c.files_total)} files</div></div>
            <span class="pill" style="background:rgba(255,255,255,0.16);color:#fff;border-color:rgba(255,255,255,0.28);">${verified ? (a.pii_leaked === 0 ? "0.0% LEAKAGE" : "LEAKS FOUND") : "UNVERIFIED"}</span>
          </div>
          <div class="kpi-value-row"><div class="kpi-value" style="font-size:22px;">${esc(medPres)}</div></div>
          <div class="kpi-footer" data-nav="clinical"><span>PII remaining: ${esc(piiRemaining)}</span><span>Clinical details →</span></div>
        </div>

        <div class="kpi-card">
          <div class="kpi-top">
            <div><div class="kpi-title">Records Linked</div><div class="kpi-sub">Processed: ${fmtNum(c.records_processed)} records</div></div>
            <span class="pill pill-offline">IDENTITY GUARD</span>
          </div>
          <div class="kpi-value-row">
            <div class="kpi-value">${fmtNum(c.records_linked)}</div>
            <span class="kpi-delta" style="background:var(--ok-soft);color:#a7f3d0;">${verified && a.linking ? `P ${a.linking.precision} • R ${a.linking.recall} • F0.5 ${a.linking.f05}` : "Conservative Linkage"}</span>
          </div>
          <div class="kpi-footer" data-nav="linkage"><span>Generalized: ${fmtNum(c.records_generalized)} • Suppressed: ${fmtNum(c.records_suppressed)}</span><span>Linkage explorer →</span></div>
        </div>

        <div class="kpi-card">
          <div class="kpi-top">
            <div><div class="kpi-title">Quarantine &amp; Resources</div><div class="kpi-sub">Identifiers detected: ${fmtNum(c.identifiers_detected)}</div></div>
            <span class="pill ${c.files_quarantined > 0 ? "pill-warn" : "pill-ok"}">SENTINEL + VAULT</span>
          </div>
          <div class="kpi-value-row">
            <div class="kpi-value">${fmtNum(c.files_quarantined)} <span class="kpi-sub">quarantined</span></div>
          </div>
          <div class="kpi-footer" data-nav="audit"><span>Time: ${esc(ov.timing?.seconds ?? 0)}s • Peak RAM: ${esc(rssVal)}</span><span>File audit →</span></div>
        </div>
      </div>

      <div class="kpi-grid-4">
        <div class="card"><div class="kpi-sub">Total Files</div><div class="kpi-value">${fmtNum(c.files_total)}</div></div>
        <div class="card"><div class="kpi-sub">Sanitized / Quarantined</div><div class="kpi-value">${fmtNum(c.files_sanitized)} / ${fmtNum(c.files_quarantined)}</div></div>
        <div class="card"><div class="kpi-sub">Identifiers Detected</div><div class="kpi-value">${fmtNum(c.identifiers_detected)}</div></div>
        <div class="card"><div class="kpi-sub">Generalized / Suppressed</div><div class="kpi-value">${fmtNum(c.records_generalized)} / ${fmtNum(c.records_suppressed)}</div></div>
      </div>

      <div class="split-grid">
        <div class="card">
          <div class="chart-header">
            <div><div class="kpi-title">Three-Layer Security Architecture</div><div class="kpi-sub">Live run-derived states</div></div>
            <button class="btn btn-sm" data-nav="pipeline">Open Pipeline →</button>
          </div>
          <div class="layer-grid">
            ${(ov.layers || []).map((layer) => `
              <div class="layer-card">
                <div class="layer-head">
                  <span class="layer-name">${esc(layer.name)}</span>
                  <span class="pill ${layer.state === "VERIFIED" || layer.state === "COMPLETED" ? "pill-ok" : "pill-warn"}">${esc(layer.state)}</span>
                </div>
                <div class="layer-sub">${esc(layer.subtitle)}</div>
                <p class="layer-purpose">${esc(layer.purpose)}</p>
                <div class="layer-stats">
                  ${(layer.details || []).map((d) => `
                    <div class="layer-stat-row"><span>${esc(d.label)}</span><strong>${esc(typeof d.value === "number" ? fmtNum(d.value) : d.value)}</strong></div>
                  `).join("")}
                </div>
              </div>
            `).join("")}
          </div>
        </div>

        <div class="card">
          <div class="chart-header">
            <div><div class="kpi-title">Detected Entities (Top Categories)</div><div class="chart-total">${fmtNum(c.identifiers_detected)} <span class="kpi-sub" style="font-weight:400;">detected</span></div></div>
            <button class="btn btn-sm" data-nav="analytics">Analytics →</button>
          </div>
          <div class="bar-chart">
            ${entEntries.map(([name, val], idx) => {
              const hPct = Math.max(8, Math.round((val / maxEnt) * 100));
              return `
                <div class="bar-col ${idx === 0 ? "highlight" : ""}" title="${esc(name)}: ${fmtNum(val)}">
                  <div class="bar-val">${fmtNum(val)}</div>
                  <div class="bar-fill" style="height:${hPct}%;"></div>
                  <div class="bar-lbl">${esc(name)}</div>
                </div>
              `;
            }).join("")}
          </div>
        </div>
      </div>

      <div class="card">
        <div class="table-toolbar">
          <div><div class="kpi-title">Run File Audit Preview</div><div class="kpi-sub">Safe paths only (PII filenames sanitized)</div></div>
          <button class="btn btn-sm" data-nav="audit">All ${fmtNum(state.filesResp.total)} Files →</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Safe Name</th><th>Format</th><th>Status</th><th>Records</th><th>Linked</th><th>Reason</th></tr></thead>
            <tbody>
              ${recentFiles.map((f) => `
                <tr>
                  <td class="mono">${esc(f.display_name)}</td>
                  <td>${esc(f.file_type)}</td>
                  <td><span class="pill ${f.status === "sanitized" ? "pill-ok" : "pill-warn"}">${esc(f.status)}</span></td>
                  <td>${fmtNum(f.records)}</td>
                  <td>${fmtNum(f.linked_records)}</td>
                  <td>${esc(f.reason || "Exported")}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      </div>
    `;
    el.querySelectorAll("[data-nav]").forEach((n) => n.addEventListener("click", () => navigate(n.dataset.nav)));
  }

  /* ------------------------------------------------------------------ */
  /* PAGE 2: DATASETS & PRE-PROCESSING INSPECTION                       */
  /* ------------------------------------------------------------------ */
  function renderIngestion() {
    const el = document.getElementById("page-ingestion");
    const inv = state.inspection;

    el.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">Datasets &amp; Pre-Processing Inspection</h1>
          <p class="page-sub">Select a local/uploaded dataset or upload new files/folders. Original files are never modified; PII filenames are masked.</p>
        </div>
        <span class="pill pill-offline">LOCAL PROCESSING ONLY</span>
      </div>

      <div class="equal-grid">
        <div class="card">
          <div class="kpi-title" style="margin-bottom:10px;">Upload New Dataset (Files or Folder)</div>
          <div class="dropzone" id="dropzone">
            <div style="font-size:24px;margin-bottom:6px;">⇪</div>
            <div style="font-weight:600;margin-bottom:4px;">Drop files here or choose files / folder</div>
            <div class="kpi-sub" style="margin-bottom:12px;">CSV, TSV, JSON, FHIR R4 JSON, TXT (max 50 MiB/file)</div>
            <div style="display:flex;gap:8px;justify-content:center;flex-wrap:wrap;">
              <button class="btn btn-primary btn-sm" type="button" id="btn-browse-files">Browse Files</button>
              <button class="btn btn-sm" type="button" id="btn-browse-folder">Browse Folder</button>
            </div>
            <input type="file" id="file-input" multiple style="display:none;" />
            <input type="file" id="folder-input" webkitdirectory directory multiple style="display:none;" />
          </div>
          <div style="margin-top:12px;">
            <input type="text" class="input-ctrl" id="upload-ds-name" style="width:100%;margin-bottom:10px;" placeholder="Optional dataset name (e.g., Ward-B May Export)" value="${esc(state.uploadName)}" />
            ${state.uploadQueue.length ? `
              <div class="kpi-sub" style="margin-bottom:8px;">Staged: ${state.uploadQueue.length} file(s) • Total ${fmtBytes(state.uploadQueue.reduce((s, x) => s + x.size, 0))}</div>
              <div style="display:flex;gap:8px;">
                <button class="btn btn-primary btn-sm" id="btn-upload-inspect" ${state.uploadBusy ? "disabled" : ""}>${state.uploadBusy ? "Uploading & Inspecting..." : "Upload & Inspect Dataset"}</button>
                <button class="btn btn-sm" id="btn-clear-queue">Clear</button>
              </div>
            ` : `<div class="kpi-sub">No files staged for upload.</div>`}
            <div id="ingestion-feedback" style="margin-top:10px;"></div>
          </div>
        </div>

        <div class="card">
          <div class="kpi-title" style="margin-bottom:10px;">Active Dataset Summary</div>
          ${!inv ? `<p class="page-sub">Select or upload a dataset to inspect it.</p>` : `
            <div class="layer-stats" style="border-top:none;padding-top:0;gap:7px;">
              <div class="layer-stat-row"><span>Dataset Name</span><strong>${esc(inv.dataset_name)}</strong></div>
              <div class="layer-stat-row"><span>Total Files / Size</span><strong>${fmtNum(inv.total_files)} files (${fmtBytes(inv.total_bytes)})</strong></div>
              <div class="layer-stat-row"><span>Supported / Quarantine Required</span><strong>${fmtNum(inv.supported_files)} / ${fmtNum(inv.quarantine_required)}</strong></div>
              <div class="layer-stat-row"><span>Empty / Oversized Files</span><strong>${fmtNum(inv.empty_files)} / ${fmtNum(inv.oversized_files)}</strong></div>
              <div class="layer-stat-row"><span>Detected Formats</span><strong>${esc(Object.entries(inv.formats || {}).map(([k, v]) => `${k}: ${v}`).join(", "))}</strong></div>
              <div class="layer-stat-row"><span>Detected Encodings</span><strong>${esc(Object.entries(inv.encodings || {}).map(([k, v]) => `${k}: ${v}`).join(", "))}</strong></div>
            </div>
            <div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--border-subtle);">
              <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text-secondary);margin-bottom:10px;">
                <input type="checkbox" id="confirm-local-run" />
                I confirm this dataset will be processed locally by RAKSHA (no external AI or network transmission).
              </label>
              <button class="btn btn-primary" id="btn-start-inspected">Start RAKSHA Processing →</button>
            </div>
          `}
        </div>
      </div>

      ${inv ? `
        <div class="card">
          <div class="table-toolbar">
            <div><div class="kpi-title">Pre-Processing Dataset Inventory</div><div class="kpi-sub">PII-bearing filenames are masked automatically</div></div>
            <div class="topbar-right">
              <button class="btn btn-sm" id="insp-prev" ${state.inspectPage <= 1 ? "disabled" : ""}>← Prev</button>
              <span class="kpi-sub">Page ${state.inspectPage}</span>
              <button class="btn btn-sm" id="insp-next" ${(inv.files || []).length < 50 ? "disabled" : ""}>Next →</button>
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>File (Masked if PII)</th><th>Format</th><th>Encoding</th><th>Size</th><th>Validation</th></tr></thead>
              <tbody>
                ${(inv.files || []).map((f) => `
                  <tr>
                    <td class="mono">${esc(f.masked_name)}</td>
                    <td>${esc(f.format)}</td>
                    <td>${esc(f.encoding)}</td>
                    <td>${fmtBytes(f.size_bytes)}</td>
                    <td><span class="pill ${f.validation === "supported" ? "pill-ok" : "pill-warn"}">${esc(f.validation === "supported" ? "Supported" : `Quarantine (${f.reason})`)}</span></td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        </div>
      ` : ""}
    `;

    const fi = document.getElementById("file-input");
    const fo = document.getElementById("folder-input");
    const dz = document.getElementById("dropzone");
    document.getElementById("btn-browse-files").addEventListener("click", () => fi.click());
    document.getElementById("btn-browse-folder").addEventListener("click", () => fo.click());
    dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.add("dragover"); });
    dz.addEventListener("dragleave", () => dz.classList.remove("dragover"));
    dz.addEventListener("drop", (e) => { e.preventDefault(); dz.classList.remove("dragover"); stageFiles(e.dataTransfer.files); });
    fi.addEventListener("change", () => stageFiles(fi.files));
    fo.addEventListener("change", () => stageFiles(fo.files));
    document.getElementById("upload-ds-name").addEventListener("input", (e) => { state.uploadName = e.target.value; });

    const clr = document.getElementById("btn-clear-queue");
    if (clr) clr.addEventListener("click", () => { state.uploadQueue = []; renderIngestion(); });
    const upBtn = document.getElementById("btn-upload-inspect");
    if (upBtn) upBtn.addEventListener("click", uploadDataset);

    const startBtn = document.getElementById("btn-start-inspected");
    if (startBtn) {
      startBtn.addEventListener("click", async () => {
        const chk = document.getElementById("confirm-local-run");
        if (!chk || !chk.checked) {
          document.getElementById("ingestion-feedback").innerHTML = `<div class="error-banner">Please confirm local processing first.</div>`;
          return;
        }
        await startRunForActiveDataset();
      });
    }

    const prev = document.getElementById("insp-prev");
    const next = document.getElementById("insp-next");
    if (prev) prev.addEventListener("click", async () => { state.inspectPage = Math.max(1, state.inspectPage - 1); await loadAllData(); });
    if (next) next.addEventListener("click", async () => { state.inspectPage += 1; await loadAllData(); });
  }

  function stageFiles(fileList) {
    for (const file of Array.from(fileList || [])) {
      state.uploadQueue.push({
        file,
        name: file.webkitRelativePath || file.name,
        size: file.size,
        format: detectFormat(file.name),
      });
    }
    renderIngestion();
  }

  function readFileAsBase64(file) {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => {
        const s = String(r.result || "");
        resolve(s.includes(",") ? s.split(",")[1] : s);
      };
      r.onerror = () => reject(new Error(`Failed to read ${file.name}`));
      r.readAsDataURL(file);
    });
  }

  async function uploadDataset() {
    state.uploadBusy = true;
    renderIngestion();
    try {
      const filesPayload = [];
      for (const item of state.uploadQueue) {
        filesPayload.push({ name: item.name, content_base64: await readFileAsBase64(item.file) });
      }
      await apiJson("/api/datasets/upload", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ dataset_name: state.uploadName || undefined, files: filesPayload }),
      });
      state.uploadQueue = [];
      state.uploadName = "";
      state.uploadBusy = false;
      state.inspectPage = 1;
      await loadAllData();
    } catch (err) {
      state.uploadBusy = false;
      renderIngestion();
      document.getElementById("ingestion-feedback").innerHTML = `<div class="error-banner">${esc(err.message)}</div>`;
    }
  }

  async function startRunForActiveDataset() {
    try {
      const res = await apiJson("/api/runs/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ dataset_id: state.activeDatasetId }),
      });
      state.activeRunId = res.run.run_id;
      await loadAllData();
      navigate("processing");
    } catch (err) {
      setError(err.message);
    }
  }

  /* ------------------------------------------------------------------ */
  /* PAGE 3: PROCESSING CONTROL CENTRE                                  */
  /* ------------------------------------------------------------------ */
  function renderProcessing() {
    const el = document.getElementById("page-processing");
    const activeRun = state.runs.find((r) => r.run_id === state.activeRunId);

    el.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">Processing Control Centre</h1>
          <p class="page-sub">Honest run lifecycle, elapsed execution time, and multi-run switching (no simulated percentages)</p>
        </div>
        <div class="topbar-right">
          <button class="btn btn-primary btn-sm" id="btn-proc-start">Start New Run</button>
          ${activeRun && activeRun.status === "processing" ? `<button class="btn btn-sm" id="btn-proc-cancel">Cancel Run</button>` : ""}
          <button class="btn btn-sm" id="btn-proc-refresh">Refresh Status</button>
        </div>
      </div>

      <div class="equal-grid">
        <div class="card">
          <div class="kpi-title" style="margin-bottom:10px;">Active Run Status</div>
          ${!activeRun ? `<p class="page-sub">No run selected for the current dataset. Click "Start New Run" to process it.</p>` : `
            <div class="layer-stats" style="border-top:none;padding-top:0;gap:8px;">
              <div class="layer-stat-row"><span>Run ID</span><strong class="mono">${esc(activeRun.run_id)}</strong></div>
              <div class="layer-stat-row"><span>Dataset</span><strong>${esc(activeRun.dataset_name)}</strong></div>
              <div class="layer-stat-row"><span>State</span><span class="pill ${activeRun.status === "completed" ? "pill-ok" : activeRun.status === "failed" ? "pill-danger" : "pill-warn"}">${esc(activeRun.status.toUpperCase())}</span></div>
              <div class="layer-stat-row"><span>Elapsed Time</span><strong>${esc(activeRun.elapsed_seconds)}s</strong></div>
              <div class="layer-stat-row"><span>Started</span><strong class="mono">${esc(activeRun.start_time)}</strong></div>
              <div class="layer-stat-row"><span>Completed</span><strong class="mono">${esc(activeRun.end_time || "In progress")}</strong></div>
              <div class="layer-stat-row"><span>Output Validation</span><strong>${esc(activeRun.contract?.status || "Pending")}</strong></div>
            </div>
            ${activeRun.error ? `<div class="error-banner" style="margin-top:12px;">${esc(activeRun.error)}</div>` : ""}
            <div style="margin-top:12px;">
              <div class="kpi-sub" style="margin-bottom:6px;">Sanitized Run Logs</div>
              <div class="preview-box" style="max-height:160px;">${esc((activeRun.logs || []).join("\n"))}</div>
            </div>
          `}
        </div>

        <div class="card">
          <div class="kpi-title" style="margin-bottom:10px;">Processing Runs History (${state.runs.length})</div>
          <div class="table-wrap" style="max-height:360px;overflow-y:auto;">
            <table>
              <thead><tr><th>Run ID</th><th>Dataset</th><th>Status</th><th>Time</th><th></th></tr></thead>
              <tbody>
                ${state.runs.map((r) => `
                  <tr>
                    <td class="mono">${esc(r.run_id)}</td>
                    <td>${esc(r.dataset_name)}</td>
                    <td><span class="pill ${r.status === "completed" ? "pill-ok" : r.status === "failed" ? "pill-danger" : "pill-warn"}">${esc(r.status)}</span></td>
                    <td>${esc(r.elapsed_seconds)}s</td>
                    <td><button class="btn btn-sm" data-sel-run="${esc(r.run_id)}">${r.run_id === state.activeRunId ? "Active" : "Open"}</button></td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    document.getElementById("btn-proc-start").addEventListener("click", startRunForActiveDataset);
    document.getElementById("btn-proc-refresh").addEventListener("click", loadAllData);
    const cbtn = document.getElementById("btn-proc-cancel");
    if (cbtn) {
      cbtn.addEventListener("click", async () => {
        await apiJson("/api/runs/cancel", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ run_id: state.activeRunId }) });
        await loadAllData();
      });
    }
    el.querySelectorAll("[data-sel-run]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        await apiJson("/api/runs/select", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ run_id: btn.dataset.selRun }) });
        await loadAllData();
      });
    });
  }

  /* ------------------------------------------------------------------ */
  /* PAGE 4: SECURITY PIPELINE                                          */
  /* ------------------------------------------------------------------ */
  function renderPipeline() {
    const el = document.getElementById("page-pipeline");
    const ov = state.overview || {};
    const layers = ov.layers || [];
    const stageCaps = {
      sentinel: ["Files discovered & inspected", "Encoding detection & UTF-8 decoding", "Unicode NFKC normalization", "Filename, header, JSON key, metadata & Base64 inspection", "Unsupported & malformed file quarantine"],
      identity_guard: ["Multilingual PII detection (Latin, Devanagari, Hinglish)", "15+ entity categories (Name, MRN, Phone, Aadhaar, ABHA, Address...)", "Identity evidence aggregation (raw PII never shown)", "Conservative patient linkage", "Ambiguous match guarding"],
      vault: ["HMAC-SHA256 pseudonymization (secret isolated)", "Per-patient date shifting", "Age banding & location generalization", "Clinical preservation & output rescan", "Quarantine & contract validation"],
    };

    el.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">Three-Layer Security Pipeline</h1>
          <p class="page-sub">SENTINEL • IDENTITY GUARD • VAULT — reflecting active run results only</p>
        </div>
        <span class="pill ${ov.contract?.ok ? "pill-ok" : "pill-warn"}">${esc(ov.contract?.status || "NO RUN")}</span>
      </div>
      ${!ov.has_output ? `<div class="card"><p class="page-sub">Run the pipeline on the active dataset to populate layer results.</p></div>` : `
        <div class="layer-grid">
          ${layers.map((layer, idx) => `
            <div class="card">
              <div class="layer-head" style="margin-bottom:8px;">
                <span class="pill pill-offline">LAYER ${idx + 1}</span>
                <span class="pill ${layer.state === "VERIFIED" || layer.state === "COMPLETED" ? "pill-ok" : "pill-warn"}">${esc(layer.state)}</span>
              </div>
              <div class="layer-name" style="font-size:16px;">${esc(layer.name)}</div>
              <div class="layer-sub" style="margin-bottom:6px;">${esc(layer.subtitle)}</div>
              <p class="layer-purpose" style="margin-bottom:12px;">${esc(layer.purpose)}</p>
              <ul style="margin:0 0 14px 16px;padding:0;color:var(--text-secondary);font-size:12px;display:flex;flex-direction:column;gap:5px;">
                ${(stageCaps[layer.id] || []).map((cap) => `<li>${esc(cap)}</li>`).join("")}
              </ul>
              <div class="layer-stats">
                ${(layer.details || []).map((d) => `<div class="layer-stat-row"><span>${esc(d.label)}</span><strong>${esc(typeof d.value === "number" ? fmtNum(d.value) : d.value)}</strong></div>`).join("")}
              </div>
            </div>
          `).join("")}
        </div>
      `}
    `;
  }

  /* ------------------------------------------------------------------ */
  /* PAGE 5: PRIVACY ANALYTICS                                          */
  /* ------------------------------------------------------------------ */
  function renderAnalytics() {
    const el = document.getElementById("page-analytics");
    const ov = state.overview || {};
    if (!ov.has_output) {
      el.innerHTML = `<div class="page-header"><h1 class="page-title">Privacy Analytics</h1></div><div class="card"><p class="page-sub">No completed run for the active dataset.</p></div>`;
      return;
    }
    const c = ov.counts || {};
    const a = ov.assurance || {};
    const verified = Boolean(a.verified);

    el.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">Privacy Analytics</h1>
          <p class="page-sub">Distinguishes Detected, Transformed, Remaining, and Not Verified metrics</p>
        </div>
        <span class="pill ${verified ? "pill-ok" : "pill-warn"}">${verified ? "EVALUATOR VERIFIED (PRACTICE)" : "NOT VERIFIED (CUSTOM RUN)"}</span>
      </div>

      <div class="kpi-grid-4">
        <div class="card"><div class="kpi-sub">Detected Entities</div><div class="kpi-value">${fmtNum(c.identifiers_detected)}</div></div>
        <div class="card"><div class="kpi-sub">Transformed / Generalized</div><div class="kpi-value">${verified ? fmtNum(a.pii_transformed) : fmtNum(c.records_generalized)}</div></div>
        <div class="card"><div class="kpi-sub">Residual PII Remaining</div><div class="kpi-value">${verified ? `${a.pii_leaked} (${a.leakage_pct}%)` : "Not verified"}</div></div>
        <div class="card"><div class="kpi-sub">Canaries / Raw Copies</div><div class="kpi-value">${verified ? `${a.canaries_leaked}/${a.canaries_total} • ${a.raw_copies}` : "Not verified"}</div></div>
      </div>

      ${verified ? `
        <div class="equal-grid">
          <div class="card">
            <div class="kpi-title" style="margin-bottom:10px;">PII by Language (Latin / Devanagari / Hinglish)</div>
            <table>
              <thead><tr><th>Language</th><th>Total</th><th>Remaining</th><th>Leakage %</th></tr></thead>
              <tbody>${(a.by_language || []).map((r) => `<tr><td>${esc(r.name)}</td><td>${fmtNum(r.total)}</td><td>${fmtNum(r.leaked)}</td><td><span class="pill ${r.leaked === 0 ? "pill-ok" : "pill-danger"}">${r.pct}%</span></td></tr>`).join("")}</tbody>
            </table>
          </div>
          <div class="card">
            <div class="kpi-title" style="margin-bottom:10px;">PII by Hiding Location</div>
            <table>
              <thead><tr><th>Location</th><th>Total</th><th>Remaining</th><th>Leakage %</th></tr></thead>
              <tbody>${(a.by_channel || []).map((r) => `<tr><td>${esc(r.name)}</td><td>${fmtNum(r.total)}</td><td>${fmtNum(r.leaked)}</td><td><span class="pill ${r.leaked === 0 ? "pill-ok" : "pill-danger"}">${r.pct}%</span></td></tr>`).join("")}</tbody>
            </table>
          </div>
        </div>
        <div class="card">
          <div class="kpi-title" style="margin-bottom:10px;">PII Entities by Category</div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Category</th><th>Total</th><th>Transformed</th><th>Remaining</th><th>Status</th></tr></thead>
              <tbody>${(a.by_type || []).map((r) => `<tr><td class="mono">${esc(r.type)}</td><td>${fmtNum(r.total)}</td><td>${fmtNum(r.transformed)}</td><td>${fmtNum(r.remaining)}</td><td><span class="pill ${r.remaining === 0 ? "pill-ok" : "pill-danger"}">${r.remaining === 0 ? "Transformed" : "Leaked"}</span></td></tr>`).join("")}</tbody>
            </table>
          </div>
        </div>
      ` : `
        <div class="card">
          <div class="kpi-title" style="margin-bottom:8px;">Detected Categories (Ground-Truth Leakage Not Verified)</div>
          <p class="page-sub" style="margin-bottom:12px;">${esc(a.reason || "")}</p>
          <table>
            <thead><tr><th>Entity Category</th><th>Detected Count</th><th>Status</th></tr></thead>
            <tbody>${Object.entries(ov.entities || {}).sort((x, y) => y[1] - x[1]).map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td>${fmtNum(v)}</td><td><span class="pill">Detected • Not verified</span></td></tr>`).join("")}</tbody>
          </table>
        </div>
      `}
    `;
  }

  /* ------------------------------------------------------------------ */
  /* PAGE 6: CLINICAL PRESERVATION                                      */
  /* ------------------------------------------------------------------ */
  function renderClinical() {
    const el = document.getElementById("page-clinical");
    const ov = state.overview || {};
    const a = ov.assurance || {};
    const verified = Boolean(ov.has_output && a.verified);

    el.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">Clinical Preservation</h1>
          <p class="page-sub">Tracks clinical utility retention (medicines, doses, frequencies, vitals, labs, diagnoses, procedures)</p>
        </div>
        <span class="pill ${verified ? "pill-ok" : "pill-warn"}">${verified ? `${a.medical_pct}% PRESERVED` : "NOT YET EVALUATED"}</span>
      </div>

      ${!verified ? `
        <div class="card">
          <div class="kpi-title">Clinical Preservation Not Yet Evaluated</div>
          <p class="page-sub" style="margin-top:6px;">
            Per-value clinical preservation requires ground-truth clinical annotations (available for the Practice Dataset; not yet evaluated for custom runs).
            ${ov.has_output ? `Records generalized safely: ${fmtNum(ov.counts?.records_generalized || 0)}.` : ""}
          </p>
        </div>
      ` : `
        <div class="kpi-grid-4">
          <div class="card"><div class="kpi-sub">Total Clinical Values Checked</div><div class="kpi-value">${fmtNum(a.medical_total)}</div></div>
          <div class="card"><div class="kpi-sub">Values Preserved</div><div class="kpi-value">${fmtNum(a.medical_kept)}</div></div>
          <div class="card"><div class="kpi-sub">Missing or Changed</div><div class="kpi-value">${fmtNum((a.medical_total || 0) - (a.medical_kept || 0))}</div></div>
          <div class="card"><div class="kpi-sub">Preservation Rate</div><div class="kpi-value">${a.medical_pct}%</div></div>
        </div>
        <div class="card">
          <div class="kpi-title" style="margin-bottom:10px;">Preservation by Clinical Category</div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Category</th><th>Preserved</th><th>Total Checked</th><th>Missing / Changed</th><th>Preservation %</th></tr></thead>
              <tbody>
                ${(a.clinical_categories || []).map((cat) => `
                  <tr>
                    <td class="mono">${esc(cat.category)}</td>
                    <td>${fmtNum(cat.preserved)}</td>
                    <td>${fmtNum(cat.total)}</td>
                    <td>${fmtNum(cat.missing)}</td>
                    <td><span class="pill ${cat.pct >= 99 ? "pill-ok" : "pill-warn"}">${cat.pct}%</span></td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        </div>
      `}
    `;
  }

  /* ------------------------------------------------------------------ */
  /* PAGE 7: PATIENT LINKAGE EXPLORER (Server-Side Paginated)           */
  /* ------------------------------------------------------------------ */
  function renderLinkage() {
    const el = document.getElementById("page-linkage");
    const resp = state.linkageResp || {};
    const s = resp.summary || {};
    const m = s.metrics;
    const recs = resp.records || [];
    const totalPages = Math.max(1, Math.ceil((resp.total || 0) / (resp.page_size || 50)));

    el.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">Patient Linkage Explorer</h1>
          <p class="page-sub">Conservative pseudonymized linkage from records.jsonl (no raw patient identifiers exposed)</p>
        </div>
        <span class="pill pill-offline">${fmtNum(s.unique_pseudonyms || 0)} Unique Pseudonyms</span>
      </div>

      <div class="kpi-grid-4">
        <div class="card"><div class="kpi-sub">Total Records</div><div class="kpi-value">${fmtNum(s.total_records || 0)}</div></div>
        <div class="card"><div class="kpi-sub">Linked Records</div><div class="kpi-value">${fmtNum(s.linked_records || 0)}</div></div>
        <div class="card"><div class="kpi-sub">Unlinked / Ambiguous</div><div class="kpi-value">${fmtNum(s.unlinked_records || 0)}</div></div>
        <div class="card">
          <div class="kpi-sub">Precision / Recall / F0.5</div>
          <div class="kpi-value" style="font-size:19px;margin-top:8px;">${m ? `${m.precision.toFixed(2)} / ${m.recall.toFixed(2)} / ${m.f05.toFixed(2)}` : "Not yet evaluated"}</div>
          <div class="kpi-sub">Wrong merges: ${m ? m.wrong_merges : "N/A"}</div>
        </div>
      </div>

      <div class="card" style="margin-bottom:16px;">
        <div class="kpi-title" style="margin-bottom:8px;">Top Pseudonym Clusters (Actual records.jsonl Clusters)</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          ${(resp.clusters || []).map((cl) => `<span class="pill pill-offline mono">${esc(cl.pseudonym)}: ${cl.records} rec (${cl.files_count} files)</span>`).join("") || `<span class="kpi-sub">No clusters in active run.</span>`}
        </div>
      </div>

      <div class="card">
        <div class="table-toolbar">
          <div class="topbar-right" style="flex-wrap:wrap;">
            <input type="text" class="input-ctrl" id="lnk-search" placeholder="Search pseudonym or file..." value="${esc(state.linkageSearch)}" />
            <select class="select-ctrl" id="lnk-status">
              <option value="all" ${state.linkageFilter === "all" ? "selected" : ""}>All Statuses</option>
              <option value="linked" ${state.linkageFilter === "linked" ? "selected" : ""}>Linked</option>
              <option value="unlinked" ${state.linkageFilter === "unlinked" ? "selected" : ""}>Unlinked / Ambiguous</option>
            </select>
            <select class="select-ctrl" id="lnk-format">
              <option value="all">All Formats</option>
              ${(resp.formats || []).map((f) => `<option value="${esc(f)}" ${state.linkageFormat === f ? "selected" : ""}>${esc(f)}</option>`).join("")}
            </select>
          </div>
          <div class="topbar-right">
            <button class="btn btn-sm" id="lnk-prev" ${state.linkagePage <= 1 ? "disabled" : ""}>← Prev</button>
            <span class="kpi-sub">Page ${state.linkagePage} / ${totalPages} (${fmtNum(resp.total || 0)})</span>
            <button class="btn btn-sm" id="lnk-next" ${state.linkagePage >= totalPages ? "disabled" : ""}>Next →</button>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Pseudonym</th><th>Sanitized Source File</th><th>Format</th><th>Location</th><th>Status</th><th>Notes</th></tr></thead>
            <tbody>
              ${recs.length === 0
                ? `<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:20px;">No records match current filters.</td></tr>`
                : recs.map((r) => `
                  <tr>
                    <td class="mono">${esc(r.patient)}</td>
                    <td class="mono">${esc(r.file)}</td>
                    <td>${esc(r.format)}</td>
                    <td class="mono">${esc(r.loc)}</td>
                    <td><span class="pill ${r.status === "linked" ? "pill-ok" : "pill-warn"}">${esc(r.status)}</span></td>
                    <td style="color:var(--text-secondary);">${esc(r.reason || "Linked")}</td>
                  </tr>
                `).join("")}
            </tbody>
          </table>
        </div>
      </div>
    `;

    const refreshLnk = async () => {
      state.linkageResp = await apiJson(`/api/linkage?status=${encodeURIComponent(state.linkageFilter)}&file=${encodeURIComponent(state.linkageFile)}&format=${encodeURIComponent(state.linkageFormat)}&q=${encodeURIComponent(state.linkageSearch)}&page=${state.linkagePage}&page_size=50`);
      renderLinkage();
    };
    document.getElementById("lnk-search").addEventListener("change", (e) => { state.linkageSearch = e.target.value; state.linkagePage = 1; refreshLnk(); });
    document.getElementById("lnk-status").addEventListener("change", (e) => { state.linkageFilter = e.target.value; state.linkagePage = 1; refreshLnk(); });
    document.getElementById("lnk-format").addEventListener("change", (e) => { state.linkageFormat = e.target.value; state.linkagePage = 1; refreshLnk(); });
    document.getElementById("lnk-prev").addEventListener("click", () => { state.linkagePage = Math.max(1, state.linkagePage - 1); refreshLnk(); });
    document.getElementById("lnk-next").addEventListener("click", () => { state.linkagePage += 1; refreshLnk(); });
  }

  /* ------------------------------------------------------------------ */
  /* PAGE 8: FILE AUDIT & QUARANTINE (Server-Side Paginated)            */
  /* ------------------------------------------------------------------ */
  function renderAudit() {
    const el = document.getElementById("page-audit");
    const resp = state.filesResp || {};
    const files = resp.files || [];
    const totalPages = Math.max(1, Math.ceil((resp.total || 0) / (resp.page_size || 50)));
    const d = state.selectedFileDetail;

    el.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">File Audit &amp; Quarantine</h1>
          <p class="page-sub">Server-side paginated audit from report.json. Quarantined payloads are never offered for download.</p>
        </div>
        <span class="pill">${fmtNum(resp.total || 0)} matching files</span>
      </div>

      <div class="split-grid">
        <div class="card">
          <div class="table-toolbar">
            <input type="text" class="input-ctrl" id="aud-search" placeholder="Search name, SHA, reason..." value="${esc(state.auditSearch)}" />
            <select class="select-ctrl" id="aud-status">
              <option value="all" ${state.auditFilter === "all" ? "selected" : ""}>All Status</option>
              <option value="sanitized" ${state.auditFilter === "sanitized" ? "selected" : ""}>Sanitized</option>
              <option value="quarantined" ${state.auditFilter === "quarantined" ? "selected" : ""}>Quarantined</option>
            </select>
            <select class="select-ctrl" id="aud-sort">
              <option value="index" ${state.auditSort === "index" ? "selected" : ""}>Order</option>
              <option value="name" ${state.auditSort === "name" ? "selected" : ""}>Name</option>
              <option value="records" ${state.auditSort === "records" ? "selected" : ""}>Records</option>
              <option value="status" ${state.auditSort === "status" ? "selected" : ""}>Status</option>
            </select>
          </div>
          <div class="table-wrap" style="max-height:480px;overflow-y:auto;">
            <table>
              <thead><tr><th>Safe Name</th><th>SHA-256</th><th>Type</th><th>Status</th><th>Recs</th><th></th></tr></thead>
              <tbody>
                ${files.map((f) => `
                  <tr>
                    <td class="mono">${esc(f.display_name)}</td>
                    <td class="mono">${esc(f.sha256_prefix)}</td>
                    <td>${esc(f.file_type)}</td>
                    <td><span class="pill ${f.status === "sanitized" ? "pill-ok" : "pill-warn"}">${esc(f.status)}</span></td>
                    <td>${fmtNum(f.records)}</td>
                    <td><button class="btn btn-sm" data-inspect="${esc(f.id)}">Inspect</button></td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
          <div style="display:flex;justify-content:space-between;align-items:center;margin-top:10px;">
            <button class="btn btn-sm" id="aud-prev" ${state.auditPage <= 1 ? "disabled" : ""}>← Prev</button>
            <span class="kpi-sub">Page ${state.auditPage} / ${totalPages}</span>
            <button class="btn btn-sm" id="aud-next" ${state.auditPage >= totalPages ? "disabled" : ""}>Next →</button>
          </div>
        </div>

        <div class="card">
          <div class="kpi-title" style="margin-bottom:8px;">File Processing Report</div>
          ${!d ? `<p class="page-sub">Select a file from the audit table to inspect its safe report and sanitized output.</p>` : `
            <div class="layer-stats" style="border-top:none;padding-top:0;gap:7px;margin-bottom:12px;">
              <div class="layer-stat-row"><span>Safe Name</span><strong class="mono">${esc(d.display_name)}</strong></div>
              <div class="layer-stat-row"><span>Input SHA-256</span><strong class="mono">${esc(d.sha256_prefix)}...</strong></div>
              <div class="layer-stat-row"><span>Status</span><span class="pill ${d.status === "sanitized" ? "pill-ok" : "pill-warn"}">${esc(d.status)}</span></div>
              <div class="layer-stat-row"><span>Records / Linked</span><strong>${fmtNum(d.records)} / ${fmtNum(d.linked_records)}</strong></div>
              ${d.reason ? `<div class="layer-stat-row"><span>Quarantine Reason</span><strong>${esc(d.reason)}</strong></div>` : ""}
            </div>
            ${d.status === "sanitized"
              ? `<div class="kpi-sub" style="margin-bottom:6px;">Sanitized Output Preview</div>
                 <div class="preview-box">${esc(d.sanitized_preview || "")}</div>
                 <div style="margin-top:10px;"><a class="btn btn-primary btn-sm" href="/api/reports/download?target=${encodeURIComponent(d.output_path)}">Download Sanitized File</a></div>`
              : `<div class="error-banner">Quarantined payload withheld (${esc(d.reason || "policy violation")}). Raw file download disabled.</div>`
            }
          `}
        </div>
      </div>
    `;

    const refreshAud = async () => {
      state.filesResp = await apiJson(`/api/files?status=${encodeURIComponent(state.auditFilter)}&format=${encodeURIComponent(state.auditFormat)}&sort=${encodeURIComponent(state.auditSort)}&q=${encodeURIComponent(state.auditSearch)}&page=${state.auditPage}&page_size=50`);
      renderAudit();
    };
    document.getElementById("aud-search").addEventListener("change", (e) => { state.auditSearch = e.target.value; state.auditPage = 1; refreshAud(); });
    document.getElementById("aud-status").addEventListener("change", (e) => { state.auditFilter = e.target.value; state.auditPage = 1; refreshAud(); });
    document.getElementById("aud-sort").addEventListener("change", (e) => { state.auditSort = e.target.value; state.auditPage = 1; refreshAud(); });
    document.getElementById("aud-prev").addEventListener("click", () => { state.auditPage = Math.max(1, state.auditPage - 1); refreshAud(); });
    document.getElementById("aud-next").addEventListener("click", () => { state.auditPage += 1; refreshAud(); });
    el.querySelectorAll("[data-inspect]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        state.selectedFileDetail = await apiJson(`/api/files/detail?id=${encodeURIComponent(btn.dataset.inspect)}`);
        renderAudit();
      });
    });
  }

  /* ------------------------------------------------------------------ */
  /* PAGE 9: REPORTS & EXPORTS                                          */
  /* ------------------------------------------------------------------ */
  function renderReports() {
    const el = document.getElementById("page-reports");
    const ov = state.overview || {};
    const ok = Boolean(ov.has_output && ov.contract && ov.contract.ok);
    const c = ov.counts || {};

    el.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">Output &amp; Report Downloads</h1>
          <p class="page-sub">Exports are enabled only after validate_output.py contract validation passes.</p>
        </div>
        <span class="pill ${ok ? "pill-ok" : "pill-danger"}">${esc(ov.contract?.status || "NO OUTPUT")}</span>
      </div>

      <div class="kpi-grid-4">
        <div class="card"><div class="kpi-sub">Contract Status</div><div class="kpi-value" style="font-size:18px;">${esc(ov.contract?.status || "NONE")}</div></div>
        <div class="card"><div class="kpi-sub">Validation Errors / Warnings</div><div class="kpi-value">${ov.contract ? `${ov.contract.errors_count} / ${ov.contract.warnings_count}` : "—"}</div></div>
        <div class="card"><div class="kpi-sub">Sanitized Output Files</div><div class="kpi-value">${fmtNum(c.files_sanitized || 0)}</div></div>
        <div class="card"><div class="kpi-sub">Quarantined (Withheld)</div><div class="kpi-value">${fmtNum(c.files_quarantined || 0)}</div></div>
      </div>

      <div class="kpi-grid-3">
        <div class="card">
          <div class="kpi-title">Full Sanitized Dataset (ZIP)</div>
          <p class="page-sub" style="margin:6px 0 14px;">Downloads all approved sanitized files + report.json + records.jsonl (quarantined files excluded).</p>
          <a class="btn btn-primary btn-sm" ${ok ? `href="/api/reports/bundle"` : `aria-disabled="true"`}>Download Sanitized Bundle (.zip)</a>
        </div>
        <div class="card">
          <div class="kpi-title">Audit Manifest (report.json)</div>
          <p class="page-sub" style="margin:6px 0 14px;">Machine-readable SHA-256 mappings, counts, and entity tallies.</p>
          <a class="btn btn-primary btn-sm" ${ok ? `href="/api/reports/download?target=report.json"` : `aria-disabled="true"`}>Download report.json</a>
        </div>
        <div class="card">
          <div class="kpi-title">Patient Linkage (records.jsonl)</div>
          <p class="page-sub" style="margin:6px 0 14px;">Pseudonymized record-to-patient mappings.</p>
          <a class="btn btn-primary btn-sm" ${ok ? `href="/api/reports/download?target=records.jsonl"` : `aria-disabled="true"`}>Download records.jsonl</a>
        </div>
      </div>
    `;
  }

  /* ------------------------------------------------------------------ */
  /* PAGE 10: SYSTEM SETTINGS                                           */
  /* ------------------------------------------------------------------ */
  function renderSettings() {
    const el = document.getElementById("page-settings");
    const sys = (state.overview && state.overview.system) || {};
    const pol = sys.policy || {};

    el.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">System Settings</h1>
          <p class="page-sub">Offline runtime posture, policy guardrails, and cryptographic configuration status</p>
        </div>
        <span class="pill pill-offline">VERSION ${esc(sys.version || "1.0.0")}</span>
      </div>
      <div class="equal-grid">
        <div class="card">
          <div class="kpi-title" style="margin-bottom:12px;">Runtime &amp; Security Posture</div>
          <div class="layer-stats" style="border-top:none;padding-top:0;gap:10px;">
            <div class="layer-stat-row"><span>Offline Runtime Mode</span><span class="pill pill-ok">${sys.offline ? "ENABLED (100% LOCAL)" : "OFF"}</span></div>
            <div class="layer-stat-row"><span>Compute Profile</span><strong>CPU-Only (Zero Cloud / LLM)</strong></div>
            <div class="layer-stat-row"><span>HMAC Secret (RAKSHA_SECRET)</span><span class="pill ${sys.secret_configured ? "pill-ok" : "pill-warn"}">${sys.secret_configured ? "Configured (Hidden)" : "Session Ephemeral"}</span></div>
            <div class="layer-stat-row"><span>Supported Formats</span><strong>${esc((sys.supported_formats || []).join(", "))}</strong></div>
          </div>
        </div>
        <div class="card">
          <div class="kpi-title" style="margin-bottom:12px;">Policy Limits (config/policy.yaml)</div>
          <div class="layer-stats" style="border-top:none;padding-top:0;gap:10px;">
            <div class="layer-stat-row"><span>Age Band Width</span><strong>${esc(pol.age_band_years || 5)} years</strong></div>
            <div class="layer-stat-row"><span>Max Date Shift</span><strong>±${esc(pol.date_shift_max_days || 180)} days</strong></div>
            <div class="layer-stat-row"><span>Min Quasi-ID Group Size (k)</span><strong>${esc(pol.min_group_size || 5)}</strong></div>
            <div class="layer-stat-row"><span>Max JSON Nesting Depth</span><strong>${esc(pol.max_json_depth || 128)}</strong></div>
            <div class="layer-stat-row"><span>Max Input File Size</span><strong>${fmtBytes(pol.max_file_bytes || 52428800)}</strong></div>
          </div>
        </div>
      </div>
    `;
  }

  /* ------------------------------------------------------------------ */
  /* GLOBAL EVENTS & TOPBAR SWITCHERS                                   */
  /* ------------------------------------------------------------------ */
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => navigate(btn.dataset.page));
  });
  document.getElementById("mobile-menu-btn").addEventListener("click", () => {
    document.getElementById("sidebar").classList.toggle("open");
  });
  document.getElementById("btn-refresh").addEventListener("click", () => loadAllData());

  document.getElementById("topbar-dataset-select").addEventListener("change", async (e) => {
    state.selectedFileDetail = null;
    state.inspectPage = 1;
    state.auditPage = 1;
    state.linkagePage = 1;
    await apiJson("/api/datasets/select", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ dataset_id: e.target.value }),
    });
    await loadAllData();
  });

  document.getElementById("topbar-run-select").addEventListener("change", async (e) => {
    if (!e.target.value) return;
    state.selectedFileDetail = null;
    state.auditPage = 1;
    state.linkagePage = 1;
    await apiJson("/api/runs/select", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ run_id: e.target.value }),
    });
    await loadAllData();
  });

  document.getElementById("global-search").addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    const q = e.target.value.trim().toLowerCase();
    if (!q) return;
    const pageHit = Object.keys(PAGE_TITLES).find((k) => PAGE_TITLES[k].toLowerCase().includes(q) || k.includes(q));
    if (pageHit) { navigate(pageHit); return; }
    state.auditSearch = e.target.value.trim();
    state.auditPage = 1;
    navigate("audit");
  });

  loadAllData();
})();
