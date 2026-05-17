"""
PDF Malware Detection - Frontend
Beautiful upload interface. Sends PDF to scanner microservice.
Shows live results + scan history dashboard.
"""

import os, requests
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

SCANNER_URL = os.getenv("SCANNER_URL", "http://scanner:5001")

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PDF Shield — Malware Detection</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;600&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:       #0a0c0f;
    --surface:  #111318;
    --border:   #1e2129;
    --accent:   #00ff88;
    --danger:   #ff3b5c;
    --warning:  #ffb800;
    --text:     #e8eaf0;
    --muted:    #5a6070;
    --mono:     'Space Mono', monospace;
    --sans:     'DM Sans', sans-serif;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    display: grid;
    grid-template-columns: 1fr;
    grid-template-rows: auto 1fr auto;
  }

  /* ── Header ── */
  header {
    border-bottom: 1px solid var(--border);
    padding: 20px 40px;
    display: flex;
    align-items: center;
    gap: 14px;
  }
  .logo-icon {
    width: 36px; height: 36px;
    background: var(--accent);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
  }
  .logo-icon svg { width: 20px; height: 20px; }
  h1 { font-family: var(--mono); font-size: 1rem; font-weight: 700; letter-spacing: 0.04em; }
  h1 span { color: var(--accent); }
  .tag {
    margin-left: auto;
    font-family: var(--mono);
    font-size: 0.65rem;
    padding: 4px 10px;
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--muted);
    letter-spacing: 0.1em;
  }

  /* ── Main layout ── */
  main {
    display: grid;
    grid-template-columns: 480px 1fr;
    gap: 1px;
    background: var(--border);
    height: calc(100vh - 65px - 48px);
  }
  .panel {
    background: var(--bg);
    padding: 40px;
    overflow-y: auto;
  }

  /* ── Upload zone ── */
  .section-label {
    font-family: var(--mono);
    font-size: 0.62rem;
    letter-spacing: 0.15em;
    color: var(--muted);
    text-transform: uppercase;
    margin-bottom: 20px;
  }
  .drop-zone {
    border: 1.5px dashed var(--border);
    border-radius: 12px;
    padding: 48px 24px;
    text-align: center;
    cursor: pointer;
    transition: border-color 0.2s, background 0.2s;
    position: relative;
    margin-bottom: 20px;
  }
  .drop-zone:hover, .drop-zone.dragover {
    border-color: var(--accent);
    background: rgba(0,255,136,0.03);
  }
  .drop-zone input[type=file] {
    position: absolute; inset: 0; opacity: 0; cursor: pointer; width: 100%; height: 100%;
  }
  .drop-icon {
    width: 48px; height: 48px;
    margin: 0 auto 16px;
    background: var(--surface);
    border-radius: 12px;
    display: flex; align-items: center; justify-content: center;
    border: 1px solid var(--border);
  }
  .drop-icon svg { width: 22px; height: 22px; stroke: var(--muted); }
  .drop-title { font-weight: 600; font-size: 0.95rem; margin-bottom: 6px; }
  .drop-sub { font-size: 0.8rem; color: var(--muted); }
  .selected-file {
    font-family: var(--mono);
    font-size: 0.75rem;
    color: var(--accent);
    margin-top: 10px;
    display: none;
  }

  /* ── Scan button ── */
  .scan-btn {
    width: 100%;
    padding: 14px;
    background: var(--accent);
    color: #000;
    border: none;
    border-radius: 8px;
    font-family: var(--mono);
    font-size: 0.85rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    cursor: pointer;
    transition: opacity 0.15s, transform 0.1s;
  }
  .scan-btn:hover   { opacity: 0.88; }
  .scan-btn:active  { transform: scale(0.98); }
  .scan-btn:disabled { opacity: 0.35; cursor: not-allowed; }

  /* ── Result card ── */
  .result-card {
    margin-top: 28px;
    border-radius: 12px;
    border: 1px solid var(--border);
    overflow: hidden;
    display: none;
  }
  .result-header {
    padding: 16px 20px;
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .result-header.malicious { background: rgba(255,59,92,0.12); border-bottom: 1px solid rgba(255,59,92,0.2); }
  .result-header.benign    { background: rgba(0,255,136,0.08); border-bottom: 1px solid rgba(0,255,136,0.15); }
  .verdict {
    font-family: var(--mono);
    font-size: 1.1rem;
    font-weight: 700;
  }
  .verdict.malicious { color: var(--danger); }
  .verdict.benign    { color: var(--accent); }
  .threat-badge {
    margin-left: auto;
    font-family: var(--mono);
    font-size: 0.65rem;
    font-weight: 700;
    padding: 4px 10px;
    border-radius: 4px;
    letter-spacing: 0.1em;
  }
  .threat-HIGH   { background: rgba(255,59,92,0.2);  color: var(--danger);  border: 1px solid rgba(255,59,92,0.3); }
  .threat-MEDIUM { background: rgba(255,184,0,0.15); color: var(--warning); border: 1px solid rgba(255,184,0,0.25); }
  .threat-LOW    { background: rgba(0,255,136,0.1);  color: var(--accent);  border: 1px solid rgba(0,255,136,0.2); }

  .result-body { padding: 20px; }
  .stat-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 0;
    border-bottom: 1px solid var(--border);
    font-size: 0.82rem;
  }
  .stat-row:last-child { border-bottom: none; }
  .stat-label { color: var(--muted); font-family: var(--mono); font-size: 0.72rem; letter-spacing: 0.05em; }
  .stat-val   { font-family: var(--mono); font-size: 0.82rem; }

  .prob-bar-wrap {
    margin-top: 16px;
    background: var(--surface);
    border-radius: 6px;
    height: 6px;
    overflow: hidden;
    border: 1px solid var(--border);
  }
  .prob-bar {
    height: 100%;
    border-radius: 6px;
    transition: width 0.6s ease;
  }
  .prob-bar.malicious { background: var(--danger); }
  .prob-bar.benign    { background: var(--accent); }

  /* ── History panel ── */
  .history-header {
    display: flex;
    align-items: baseline;
    gap: 12px;
    margin-bottom: 24px;
  }
  .stats-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 32px;
  }
  .stat-box {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px;
  }
  .stat-box-val {
    font-family: var(--mono);
    font-size: 1.5rem;
    font-weight: 700;
    margin-bottom: 4px;
  }
  .stat-box-val.danger  { color: var(--danger); }
  .stat-box-val.success { color: var(--accent); }
  .stat-box-val.warning { color: var(--warning); }
  .stat-box-label { font-size: 0.72rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; }

  /* ── History table ── */
  .history-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  .history-table th {
    text-align: left;
    padding: 8px 12px;
    color: var(--muted);
    font-family: var(--mono);
    font-size: 0.65rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    border-bottom: 1px solid var(--border);
    font-weight: 400;
  }
  .history-table td {
    padding: 12px 12px;
    border-bottom: 1px solid var(--border);
    font-family: var(--mono);
    font-size: 0.75rem;
  }
  .history-table tr:last-child td { border-bottom: none; }
  .history-table tr:hover td { background: var(--surface); }
  .pill {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.05em;
  }
  .pill-mal { background: rgba(255,59,92,0.15); color: var(--danger); }
  .pill-ben { background: rgba(0,255,136,0.1);  color: var(--accent); }

  .empty-state {
    text-align: center;
    padding: 60px 20px;
    color: var(--muted);
    font-size: 0.85rem;
  }
  .empty-state svg { width: 40px; height: 40px; stroke: var(--border); margin-bottom: 12px; }

  /* ── Loader ── */
  .loader {
    display: none;
    margin: 16px auto;
    width: 24px; height: 24px;
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Footer ── */
  footer {
    border-top: 1px solid var(--border);
    padding: 12px 40px;
    display: flex;
    align-items: center;
    gap: 8px;
    font-family: var(--mono);
    font-size: 0.65rem;
    color: var(--muted);
  }
  .status-dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--accent);
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.3; }
  }
</style>
</head>
<body>

<header>
  <div class="logo-icon">
    <svg viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.5" stroke-linecap="round">
      <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z"/>
    </svg>
  </div>
  <h1>PDF <span>Shield</span></h1>
  <span class="tag">ML-POWERED · RANDOMFOREST</span>
</header>

<main>
  <!-- Upload Panel -->
  <div class="panel">
    <div class="section-label">Scan a PDF</div>

    <div class="drop-zone" id="dropZone">
      <input type="file" id="fileInput" accept=".pdf">
      <div class="drop-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
          <polyline points="14,2 14,8 20,8"/>
          <line x1="12" y1="18" x2="12" y2="12"/>
          <line x1="9" y1="15" x2="12" y2="12"/>
          <line x1="15" y1="15" x2="12" y2="12"/>
        </svg>
      </div>
      <div class="drop-title">Drop PDF here or click to browse</div>
      <div class="drop-sub">Supports any PDF up to 20 MB</div>
    </div>
    <div class="selected-file" id="selectedFile"></div>

    <button class="scan-btn" id="scanBtn" onclick="scanFile()" disabled>SCAN FILE</button>
    <div class="loader" id="loader"></div>

    <!-- Result -->
    <div class="result-card" id="resultCard">
      <div class="result-header" id="resultHeader">
        <div class="verdict" id="verdictText"></div>
        <div class="threat-badge" id="threatBadge"></div>
      </div>
      <div class="result-body">
        <div class="stat-row">
          <span class="stat-label">FILE</span>
          <span class="stat-val" id="resFilename">—</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">CONFIDENCE</span>
          <span class="stat-val" id="resProb">—</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">SIZE (KB)</span>
          <span class="stat-val" id="resSize">—</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">JAVASCRIPT PRESENT</span>
          <span class="stat-val" id="resJS">—</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">OPEN ACTION</span>
          <span class="stat-val" id="resOA">—</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">SCANNED AT</span>
          <span class="stat-val" id="resTime">—</span>
        </div>
        <div class="prob-bar-wrap" style="margin-top:16px">
          <div class="prob-bar" id="probBar" style="width:0%"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- History Panel -->
  <div class="panel">
    <div class="history-header">
      <div class="section-label" style="margin:0">Scan History</div>
      <button onclick="loadHistory()" style="background:none;border:1px solid var(--border);color:var(--muted);
        padding:4px 10px;border-radius:4px;font-family:var(--mono);font-size:0.65rem;cursor:pointer;letter-spacing:0.08em">
        REFRESH
      </button>
    </div>

    <div class="stats-row" id="statsRow">
      <div class="stat-box">
        <div class="stat-box-val" id="st-total">—</div>
        <div class="stat-box-label">Total Scans</div>
      </div>
      <div class="stat-box">
        <div class="stat-box-val danger" id="st-mal">—</div>
        <div class="stat-box-label">Malicious</div>
      </div>
      <div class="stat-box">
        <div class="stat-box-val success" id="st-ben">—</div>
        <div class="stat-box-label">Benign</div>
      </div>
      <div class="stat-box">
        <div class="stat-box-val warning" id="st-rate">—</div>
        <div class="stat-box-label">Threat Rate</div>
      </div>
    </div>

    <div id="historyContainer">
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke-width="1" stroke-linecap="round">
          <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <div>No scans yet. Upload a PDF to get started.</div>
      </div>
    </div>
  </div>
</main>

<footer>
  <div class="status-dot"></div>
  SCANNER ACTIVE · RandomForest · 25 features · SQLite storage
</footer>

<script>
const fileInput   = document.getElementById('fileInput');
const dropZone    = document.getElementById('dropZone');
const selectedFile= document.getElementById('selectedFile');
const scanBtn     = document.getElementById('scanBtn');

fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) {
    selectedFile.style.display = 'block';
    selectedFile.textContent   = '→ ' + fileInput.files[0].name;
    scanBtn.disabled = false;
  }
});

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
  e.preventDefault(); dropZone.classList.remove('dragover');
  const f = e.dataTransfer.files[0];
  if (f && f.name.endsWith('.pdf')) {
    fileInput.files = e.dataTransfer.files;
    selectedFile.style.display = 'block';
    selectedFile.textContent   = '→ ' + f.name;
    scanBtn.disabled = false;
  }
});

async function scanFile() {
  const file = fileInput.files[0];
  if (!file) return;
  scanBtn.disabled = true;
  document.getElementById('loader').style.display = 'block';
  document.getElementById('resultCard').style.display = 'none';

  const fd = new FormData();
  fd.append('file', file);

  try {
    const res  = await fetch('/scan', { method: 'POST', body: fd });
    const data = await res.json();
    if (data.error) { alert('Error: ' + data.error); return; }
    showResult(data);
    loadHistory();
  } catch(e) {
    alert('Scan failed: ' + e.message);
  } finally {
    scanBtn.disabled = false;
    document.getElementById('loader').style.display = 'none';
  }
}

function showResult(d) {
  const card = document.getElementById('resultCard');
  const hdr  = document.getElementById('resultHeader');
  const cls  = d.prediction === 'Malicious' ? 'malicious' : 'benign';

  card.style.display = 'block';
  hdr.className      = 'result-header ' + cls;
  document.getElementById('verdictText').className    = 'verdict ' + cls;
  document.getElementById('verdictText').textContent  = d.prediction.toUpperCase();
  document.getElementById('threatBadge').className    = 'threat-badge threat-' + d.threat_level;
  document.getElementById('threatBadge').textContent  = d.threat_level + ' THREAT';
  document.getElementById('resFilename').textContent  = d.filename;
  document.getElementById('resProb').textContent      = (d.probability * 100).toFixed(1) + '%';
  document.getElementById('resSize').textContent      = d.features?.pdfsize || '—';
  document.getElementById('resJS').textContent        = d.features?.has_javascript ? 'YES ⚠' : 'No';
  document.getElementById('resOA').textContent        = d.features?.OpenAction ? 'YES ⚠' : 'No';
  document.getElementById('resTime').textContent      = new Date(d.scanned_at + 'Z').toLocaleTimeString();

  const bar = document.getElementById('probBar');
  bar.className = 'prob-bar ' + cls;
  setTimeout(() => { bar.style.width = (d.probability * 100) + '%'; }, 50);
}

async function loadHistory() {
  try {
    const [histRes, statsRes] = await Promise.all([fetch('/history'), fetch('/stats')]);
    const history = await histRes.json();
    const stats   = await statsRes.json();

    document.getElementById('st-total').textContent = stats.total_scans;
    document.getElementById('st-mal').textContent   = stats.malicious;
    document.getElementById('st-ben').textContent   = stats.benign;
    document.getElementById('st-rate').textContent  = stats.malicious_rate + '%';

    const container = document.getElementById('historyContainer');
    if (!history.length) {
      container.innerHTML = `<div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke-width="1" stroke-linecap="round">
          <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg><div>No scans yet.</div></div>`;
      return;
    }

    container.innerHTML = `<table class="history-table">
      <thead><tr>
        <th>File</th><th>Verdict</th><th>Threat</th><th>Confidence</th><th>Time</th>
      </tr></thead>
      <tbody>
        ${history.map(r => `<tr>
          <td>${r.filename}</td>
          <td><span class="pill ${r.prediction==='Malicious'?'pill-mal':'pill-ben'}">${r.prediction}</span></td>
          <td>${r.threat}</td>
          <td>${(r.probability*100).toFixed(1)}%</td>
          <td>${new Date(r.scanned_at+'Z').toLocaleTimeString()}</td>
        </tr>`).join('')}
      </tbody>
    </table>`;
  } catch(e) { console.error(e); }
}

loadHistory();
</script>
</body>
</html>"""

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/scan", methods=["POST"])
def scan():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400
    file = request.files["file"]
    try:
        resp = requests.post(
            f"{SCANNER_URL}/scan",
            files={"file": (file.filename, file.read(), "application/pdf")},
            timeout=30,
        )
        return jsonify(resp.json()), resp.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Scanner service unavailable"}), 503

@app.route("/history")
def history():
    try:
        r = requests.get(f"{SCANNER_URL}/history", timeout=5)
        return jsonify(r.json())
    except:
        return jsonify([])

@app.route("/stats")
def stats():
    try:
        r = requests.get(f"{SCANNER_URL}/stats", timeout=5)
        return jsonify(r.json())
    except:
        return jsonify({"total_scans":0,"malicious":0,"benign":0,"high_threat":0,"malicious_rate":0})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)
