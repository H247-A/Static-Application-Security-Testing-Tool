"""
web.py — Flask web interface for the SAST scanner
Features: file upload, severity filters, JSON export, scan history
Run: python web.py  →  open http://localhost:5000
"""

from flask import Flask, request, jsonify, render_template_string
import os, sys, json
sys.path.insert(0, os.path.dirname(__file__))
from analyzer import analyze_source
from rules import SEVERITY_RANK, RULES_META

app = Flask(__name__)

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAST Security Scanner</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh;display:flex;flex-direction:column}
header{background:#1a1d2e;border-bottom:1px solid #2d3748;padding:14px 24px;display:flex;align-items:center;gap:12px;flex-shrink:0}
header h1{font-size:17px;font-weight:700;color:#fff}
.chip{font-size:11px;background:#2d3748;padding:3px 10px;border-radius:20px;color:#94a3b8}
.main{display:grid;grid-template-columns:1fr 1fr;flex:1;min-height:0;height:calc(100vh - 53px)}

/* LEFT PANE */
.left-pane{display:flex;flex-direction:column;border-right:1px solid #2d3748}
.pane-header{padding:12px 18px;background:#1a1d2e;border-bottom:1px solid #2d3748;display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.pane-header h2{font-size:11px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.08em}

/* Drop zone */
.drop-zone{margin:12px 16px;border:1.5px dashed #2d3748;border-radius:8px;padding:18px;text-align:center;cursor:pointer;transition:all .2s;flex-shrink:0}
.drop-zone:hover,.drop-zone.drag-over{border-color:#3b82f6;background:#1a2744}
.drop-zone p{font-size:12px;color:#64748b;margin-top:4px}
.drop-zone strong{font-size:13px;color:#94a3b8}
.drop-zone input{display:none}

textarea{flex:1;background:#0d1117;color:#e2e8f0;border:none;resize:none;padding:16px 18px;font-family:'JetBrains Mono','Fira Code',monospace;font-size:12.5px;line-height:1.65;outline:none;tab-size:4;min-height:0}
textarea::placeholder{color:#374151}

.controls{padding:10px 16px;background:#1a1d2e;border-top:1px solid #2d3748;display:flex;gap:8px;align-items:center;flex-shrink:0}
.fname{background:#0d1117;color:#e2e8f0;border:1px solid #2d3748;padding:7px 10px;border-radius:6px;font-size:12px;width:140px;outline:none}
.fname:focus{border-color:#3b82f6}
.btn{padding:8px 18px;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;border:none;transition:all .15s}
.btn-scan{background:#3b82f6;color:#fff}
.btn-scan:hover{background:#2563eb}
.btn-scan:disabled{background:#1e3a5f;color:#64748b;cursor:not-allowed}
.btn-ghost{background:transparent;color:#64748b;border:1px solid #2d3748}
.btn-ghost:hover{color:#94a3b8;border-color:#4a5568}
.line-count{margin-left:auto;font-size:11px;color:#4a5568}

/* RIGHT PANE */
.right-pane{display:flex;flex-direction:column;overflow:hidden}
.tab-bar{display:flex;border-bottom:1px solid #2d3748;background:#1a1d2e;flex-shrink:0}
.tab{padding:10px 16px;font-size:11px;font-weight:600;color:#64748b;cursor:pointer;border-bottom:2px solid transparent;text-transform:uppercase;letter-spacing:.06em;transition:color .15s}
.tab.active{color:#3b82f6;border-bottom-color:#3b82f6}

/* Summary bar */
.summary-bar{padding:10px 18px;background:#1a1d2e;border-bottom:1px solid #2d3748;display:none;align-items:center;gap:12px;flex-shrink:0}
.sstat{font-size:12px;display:flex;align-items:center;gap:5px}
.sstat .n{font-weight:700;font-size:14px}
.c{color:#a855f7}.h{color:#ef4444}.m{color:#f59e0b}.l{color:#3b82f6}

/* Filter bar */
.filter-bar{padding:8px 18px;background:#131620;border-bottom:1px solid #1e2535;display:none;gap:6px;flex-shrink:0}
.filter-btn{padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid transparent;transition:all .15s;letter-spacing:.04em}
.filter-btn.all{background:#2d3748;color:#94a3b8;border-color:#374151}
.filter-btn.all.active{background:#3b82f6;color:#fff;border-color:#3b82f6}
.filter-btn.crit{background:#1f0a2e;color:#a855f7;border-color:#581c87}
.filter-btn.crit.active{background:#581c87;color:#e9d5ff}
.filter-btn.high{background:#1f0a0a;color:#f87171;border-color:#7f1d1d}
.filter-btn.high.active{background:#7f1d1d;color:#fecaca}
.filter-btn.med{background:#1f1208;color:#fbbf24;border-color:#78350f}
.filter-btn.med.active{background:#78350f;color:#fde68a}
.filter-btn.low{background:#0a0f1f;color:#60a5fa;border-color:#1e3a5f}
.filter-btn.low.active{background:#1e3a5f;color:#bfdbfe}

/* Export bar */
.export-bar{padding:8px 18px;background:#131620;border-bottom:1px solid #1e2535;display:none;gap:8px;align-items:center;flex-shrink:0}
.btn-export{padding:5px 14px;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid #2d3748;background:#1a1d2e;color:#94a3b8;transition:all .15s}
.btn-export:hover{background:#2d3748;color:#e2e8f0}
.export-label{font-size:11px;color:#4a5568;text-transform:uppercase;letter-spacing:.06em}

/* Results */
.results-body{flex:1;overflow-y:auto}
.finding{border-bottom:1px solid #1a2030;padding:14px 18px;transition:background .1s;cursor:default}
.finding:hover{background:#141824}
.finding.hidden{display:none}
.finding-top{display:flex;align-items:center;gap:7px;margin-bottom:5px}
.badge{font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;letter-spacing:.04em}
.badge-CRITICAL{background:#581c87;color:#e9d5ff}
.badge-HIGH{background:#7f1d1d;color:#fecaca}
.badge-MEDIUM{background:#78350f;color:#fde68a}
.badge-LOW{background:#1e3a5f;color:#bfdbfe}
.rule-tag{font-family:monospace;font-size:10px;color:#64748b;background:#1e2535;padding:2px 6px;border-radius:3px}
.cwe-tag{font-size:10px;color:#4a5568;font-family:monospace}
.finding-title{font-size:13px;font-weight:600;color:#f1f5f9;margin-bottom:3px}
.finding-loc{font-family:monospace;font-size:10px;color:#4a5568;margin-bottom:6px}
.finding-detail{font-size:12px;color:#94a3b8;line-height:1.5;margin-bottom:5px}
.finding-fix{font-size:12px;color:#4ade80;line-height:1.5}
.finding-fix::before{content:"Fix: ";color:#4a5568}

/* States */
.empty-state,.loading-state,.clean-state{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;gap:10px;color:#4a5568}
.empty-state svg,.clean-state svg{opacity:.25}
.empty-state p,.loading-state p{font-size:13px}
.clean-state{color:#22c55e}
.clean-state p{color:#94a3b8;font-size:13px}
@keyframes spin{to{transform:rotate(360deg)}}
.spinner{width:20px;height:20px;border:2px solid #2d3748;border-top-color:#3b82f6;border-radius:50%;animation:spin .6s linear infinite}

/* Rules tab */
.rules-list{padding:0;overflow-y:auto;flex:1}
.rule-row{display:flex;gap:10px;align-items:center;padding:11px 18px;border-bottom:1px solid #1a2030}
.rule-row:hover{background:#141824}
.rule-id-tag{font-family:monospace;font-size:11px;color:#64748b;background:#1e2535;padding:2px 7px;border-radius:3px;min-width:42px;text-align:center}
.rule-name{font-size:13px;color:#e2e8f0}
.rule-cwe{font-size:11px;color:#4a5568;font-family:monospace}

/* History tab */
.history-list{overflow-y:auto;flex:1}
.history-item{padding:12px 18px;border-bottom:1px solid #1a2030;cursor:pointer;transition:background .1s}
.history-item:hover{background:#141824}
.history-meta{font-size:11px;color:#4a5568;margin-bottom:3px}
.history-title{font-size:13px;color:#e2e8f0;font-weight:500}
.history-badges{display:flex;gap:5px;margin-top:5px}
.no-history{display:flex;align-items:center;justify-content:center;height:100%;color:#4a5568;font-size:13px}
</style>
</head>
<body>
<header>
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>
  <h1>SAST Security Scanner</h1>
  <span class="chip">CMPE 279 — SJSU Spring 2026</span>
  <span class="chip" style="margin-left:auto">20 rules · 12 CWE categories</span>
</header>

<div class="main">
  <!-- LEFT: code input -->
  <div class="left-pane">
    <div class="pane-header">
      <h2>Source Code</h2>
      <input class="fname" id="filename" value="app.py" placeholder="filename.py">
    </div>

    <!-- Drag & drop zone -->
    <div class="drop-zone" id="dropZone" onclick="document.getElementById('fileInput').click()"
         ondragover="handleDragOver(event)" ondragleave="handleDragLeave(event)" ondrop="handleDrop(event)">
      <input type="file" id="fileInput" accept=".py" onchange="handleFileSelect(event)">
      <strong>📂 Drop a .py file here</strong>
      <p>or click to browse</p>
    </div>

    <textarea id="code" placeholder="Or paste Python code here...">{{ sample }}</textarea>

    <div class="controls">
      <button class="btn btn-scan" id="scanBtn" onclick="scan()">▶ Scan</button>
      <button class="btn btn-ghost" onclick="clearAll()">Clear</button>
      <span class="line-count" id="linecount">39 lines</span>
    </div>
  </div>

  <!-- RIGHT: results -->
  <div class="right-pane">
    <div class="tab-bar">
      <div class="tab active" id="tab-findings-btn" onclick="switchTab('findings',this)">Findings</div>
      <div class="tab" id="tab-rules-btn"    onclick="switchTab('rules',this)">All Rules (20)</div>
      <div class="tab" id="tab-history-btn"  onclick="switchTab('history',this)">History</div>
    </div>

    <!-- FINDINGS tab -->
    <div id="tab-findings" style="display:flex;flex-direction:column;flex:1;overflow:hidden;min-height:0">
      <div class="summary-bar" id="summary-bar"></div>

      <!-- Filter buttons -->
      <div class="filter-bar" id="filter-bar">
        <span style="font-size:11px;color:#4a5568;text-transform:uppercase;letter-spacing:.06em;margin-right:4px">Filter:</span>
        <button class="filter-btn all active" onclick="setFilter('ALL',this)">All</button>
        <button class="filter-btn crit" onclick="setFilter('CRITICAL',this)">Critical</button>
        <button class="filter-btn high" onclick="setFilter('HIGH',this)">High</button>
        <button class="filter-btn med"  onclick="setFilter('MEDIUM',this)">Medium</button>
        <button class="filter-btn low"  onclick="setFilter('LOW',this)">Low</button>
      </div>

      <!-- Export bar -->
      <div class="export-bar" id="export-bar">
        <span class="export-label">Export:</span>
        <button class="btn-export" onclick="exportJSON()">⬇ JSON</button>
        <button class="btn-export" onclick="exportCSV()">⬇ CSV</button>
        <button class="btn-export" onclick="exportTXT()">⬇ TXT Report</button>
      </div>

      <div class="results-body" id="results">
        <div class="empty-state">
          <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
          </svg>
          <p>Drop a file or paste code, then click Scan</p>
        </div>
      </div>
    </div>

    <!-- RULES tab -->
    <div id="tab-rules" style="display:none;flex-direction:column;flex:1;overflow:hidden;min-height:0">
      <div class="rules-list">
        {% for rid, cwe, sev, name in rules %}
        <div class="rule-row">
          <span class="rule-id-tag">{{rid}}</span>
          <span class="badge badge-{{sev}}" style="min-width:68px;text-align:center">{{sev}}</span>
          <div>
            <div class="rule-name">{{name}}</div>
            <div class="rule-cwe">{{cwe}}</div>
          </div>
        </div>
        {% endfor %}
      </div>
    </div>

    <!-- HISTORY tab -->
    <div id="tab-history" style="display:none;flex-direction:column;flex:1;overflow:hidden;min-height:0">
      <div class="history-list" id="history-list">
        <div class="no-history">No scans yet</div>
      </div>
    </div>
  </div>
</div>

<script>
const SEV_ORDER = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
let lastFindings = [];
let scanHistory  = [];
let activeFilter = 'ALL';

// ── line count ────────────────────────────────────────────────
function updateLineCount(){
  const n = document.getElementById('code').value.split('\\n').length;
  document.getElementById('linecount').textContent = n + ' lines';
}
document.getElementById('code').addEventListener('input', updateLineCount);
updateLineCount();

// ── drag & drop ───────────────────────────────────────────────
function handleDragOver(e){
  e.preventDefault();
  document.getElementById('dropZone').classList.add('drag-over');
}
function handleDragLeave(e){
  document.getElementById('dropZone').classList.remove('drag-over');
}
function handleDrop(e){
  e.preventDefault();
  document.getElementById('dropZone').classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if(file) loadFile(file);
}
function handleFileSelect(e){
  const file = e.target.files[0];
  if(file) loadFile(file);
}
function loadFile(file){
  if(!file.name.endsWith('.py')){
    alert('Please upload a .py file');
    return;
  }
  document.getElementById('filename').value = file.name;
  const reader = new FileReader();
  reader.onload = e => {
    document.getElementById('code').value = e.target.result;
    updateLineCount();
  };
  reader.readAsText(file);
}

// ── tabs ──────────────────────────────────────────────────────
function switchTab(tab, el){
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  ['findings','rules','history'].forEach(t => {
    document.getElementById('tab-'+t).style.display = t === tab ? 'flex' : 'none';
  });
}

// ── filter ────────────────────────────────────────────────────
function setFilter(sev, btn){
  activeFilter = sev;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.finding').forEach(el => {
    el.classList.toggle('hidden', sev !== 'ALL' && el.dataset.sev !== sev);
  });
}

// ── clear ─────────────────────────────────────────────────────
function clearAll(){
  document.getElementById('code').value = '';
  document.getElementById('filename').value = 'app.py';
  updateLineCount();
  resetResults();
}
function resetResults(){
  lastFindings = [];
  activeFilter = 'ALL';
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  document.querySelector('.filter-btn.all').classList.add('active');
  document.getElementById('summary-bar').style.display = 'none';
  document.getElementById('filter-bar').style.display  = 'none';
  document.getElementById('export-bar').style.display  = 'none';
  document.getElementById('results').innerHTML = `
    <div class="empty-state">
      <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
      </svg>
      <p>Drop a file or paste code, then click Scan</p>
    </div>`;
}

// ── scan ──────────────────────────────────────────────────────
async function scan(){
  const code     = document.getElementById('code').value.trim();
  const filename = document.getElementById('filename').value || 'code.py';
  if(!code) return;

  const btn = document.getElementById('scanBtn');
  btn.disabled = true; btn.textContent = 'Scanning...';

  document.getElementById('results').innerHTML = '<div class="loading-state"><div class="spinner"></div><p>Analyzing code...</p></div>';
  document.getElementById('summary-bar').style.display = 'none';
  document.getElementById('filter-bar').style.display  = 'none';
  document.getElementById('export-bar').style.display  = 'none';

  try {
    const resp = await fetch('/scan', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({code, filename})
    });
    const data = await resp.json();
    lastFindings = data.findings || [];
    renderFindings(lastFindings, filename);
    addToHistory(filename, lastFindings);
  } catch(e) {
    document.getElementById('results').innerHTML = '<div class="empty-state"><p style="color:#ef4444">Scan failed — check server.</p></div>';
  }

  btn.disabled = false; btn.textContent = '▶ Scan';
}

function renderFindings(findings, filename){
  const bar    = document.getElementById('summary-bar');
  const fbar   = document.getElementById('filter-bar');
  const ebar   = document.getElementById('export-bar');

  if(findings.length === 0){
    document.getElementById('results').innerHTML = `
      <div class="clean-state">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
        </svg>
        <p>No vulnerabilities detected</p>
      </div>`;
    bar.style.display = fbar.style.display = ebar.style.display = 'none';
    return;
  }

  const counts = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  findings.forEach(f => { if(counts[f.severity]!==undefined) counts[f.severity]++; });

  bar.style.display  = 'flex';
  fbar.style.display = 'flex';
  ebar.style.display = 'flex';

  bar.innerHTML = `
    <span class="sstat"><span class="n" style="color:#e2e8f0">${findings.length}</span><span style="color:#4a5568;font-size:11px">findings</span></span>
    <span style="color:#2d3748">|</span>
    ${counts.CRITICAL?`<span class="sstat c"><span class="n">${counts.CRITICAL}</span>Critical</span>`:''}
    ${counts.HIGH    ?`<span class="sstat h"><span class="n">${counts.HIGH}</span>High</span>`:''}
    ${counts.MEDIUM  ?`<span class="sstat m"><span class="n">${counts.MEDIUM}</span>Medium</span>`:''}
    ${counts.LOW     ?`<span class="sstat l"><span class="n">${counts.LOW}</span>Low</span>`:''}
  `;

  const sorted = [...findings].sort((a,b)=>(SEV_ORDER[a.severity]||9)-(SEV_ORDER[b.severity]||9));
  document.getElementById('results').innerHTML = sorted.map(f=>`
    <div class="finding" data-sev="${f.severity}">
      <div class="finding-top">
        <span class="badge badge-${f.severity}">${f.severity}</span>
        <span class="rule-tag">${f.rule_id}</span>
        <span class="cwe-tag">${f.cwe}</span>
      </div>
      <div class="finding-title">${f.title}</div>
      <div class="finding-loc">${f.filename}:${f.line}:${f.col}</div>
      <div class="finding-detail">${f.detail}</div>
      <div class="finding-fix">${f.fix}</div>
    </div>
  `).join('');

  // reapply active filter
  if(activeFilter !== 'ALL') setFilter(activeFilter, document.querySelector('.filter-btn.'+activeFilter.toLowerCase()) || document.querySelector('.filter-btn.all'));
}

// ── history ───────────────────────────────────────────────────
function addToHistory(filename, findings){
  const counts = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  findings.forEach(f => { if(counts[f.severity]!==undefined) counts[f.severity]++; });
  const entry = { filename, findings, counts, time: new Date().toLocaleTimeString() };
  scanHistory.unshift(entry);
  renderHistory();
}

function renderHistory(){
  const list = document.getElementById('history-list');
  if(scanHistory.length === 0){
    list.innerHTML = '<div class="no-history">No scans yet</div>';
    return;
  }
  list.innerHTML = scanHistory.map((e,i) => `
    <div class="history-item" onclick="loadHistoryItem(${i})">
      <div class="history-meta">${e.time} — ${e.findings.length} finding(s)</div>
      <div class="history-title">${e.filename}</div>
      <div class="history-badges">
        ${e.counts.CRITICAL?`<span class="badge badge-CRITICAL">${e.counts.CRITICAL} Critical</span>`:''}
        ${e.counts.HIGH    ?`<span class="badge badge-HIGH">${e.counts.HIGH} High</span>`:''}
        ${e.counts.MEDIUM  ?`<span class="badge badge-MEDIUM">${e.counts.MEDIUM} Medium</span>`:''}
        ${e.counts.LOW     ?`<span class="badge badge-LOW">${e.counts.LOW} Low</span>`:''}
        ${e.findings.length===0?`<span style="font-size:11px;color:#22c55e">✓ Clean</span>`:''}
      </div>
    </div>
  `).join('');
}

function loadHistoryItem(i){
  lastFindings = scanHistory[i].findings;
  switchTab('findings', document.getElementById('tab-findings-btn'));
  renderFindings(lastFindings, scanHistory[i].filename);
}

// ── export ────────────────────────────────────────────────────
function exportJSON(){
  if(!lastFindings.length) return;
  const blob = new Blob([JSON.stringify({
    tool: "SAST Security Scanner — CMPE 279",
    generated: new Date().toISOString(),
    total: lastFindings.length,
    findings: lastFindings
  }, null, 2)], {type:'application/json'});
  downloadBlob(blob, 'sast_report.json');
}

function exportCSV(){
  if(!lastFindings.length) return;
  const header = 'Rule ID,CWE,Severity,Title,File,Line,Detail,Fix';
  const rows = lastFindings.map(f =>
    [f.rule_id, f.cwe, f.severity, `"${f.title}"`, f.filename, f.line, `"${f.detail}"`, `"${f.fix}"`].join(',')
  );
  const blob = new Blob([[header,...rows].join('\\n')], {type:'text/csv'});
  downloadBlob(blob, 'sast_report.csv');
}

function exportTXT(){
  if(!lastFindings.length) return;
  const lines = [
    'SAST SECURITY REPORT',
    'Tool: SAST Scanner — CMPE 279, SJSU Spring 2026',
    'Generated: ' + new Date().toLocaleString(),
    'Total Findings: ' + lastFindings.length,
    '='.repeat(60),
    ''
  ];
  const sorted = [...lastFindings].sort((a,b)=>(SEV_ORDER[a.severity]||9)-(SEV_ORDER[b.severity]||9));
  sorted.forEach(f => {
    lines.push(`[${f.severity}] ${f.rule_id} — ${f.title}`);
    lines.push(`  Location : ${f.filename}:${f.line}:${f.col}`);
    lines.push(`  CWE      : ${f.cwe}`);
    lines.push(`  Issue    : ${f.detail}`);
    lines.push(`  Fix      : ${f.fix}`);
    lines.push('');
  });
  const blob = new Blob([lines.join('\\n')], {type:'text/plain'});
  downloadBlob(blob, 'sast_report.txt');
}

function downloadBlob(blob, filename){
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ── keyboard shortcut ─────────────────────────────────────────
document.addEventListener('keydown', e => {
  if((e.ctrlKey||e.metaKey) && e.key==='Enter') scan();
});
</script>
</body>
</html>"""

SAMPLE_CODE = '''import hashlib, pickle, os, subprocess, random
import requests, yaml
import xml.etree.ElementTree as ET
from flask import Flask, request, redirect, render_template_string, make_response

app = Flask(__name__)
secret_key = "flask-dev-secret"

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = hashlib.md5(password.encode()).hexdigest()
    query = "SELECT * FROM users WHERE username = \'%s\'" % username
    cursor.execute(query)
    token = str(random.randint(100000, 999999))
    resp = make_response(redirect("/dashboard"))
    resp.set_cookie("session", token)
    return resp

@app.route("/search")
def search():
    q = request.args.get("q")
    return render_template_string("<h1>" + q + "</h1>")

@app.route("/admin")
def admin():
    cmd = request.args.get("cmd")
    subprocess.run(cmd, shell=True)
    data = request.get_data()
    return str(pickle.loads(data))

@app.route("/go")
def go():
    url = request.args.get("next")
    return redirect(url)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
'''


@app.route("/")
def index():
    return render_template_string(HTML, rules=RULES_META, sample=SAMPLE_CODE)


@app.route("/scan", methods=["POST"])
def scan():
    data     = request.get_json()
    code     = data.get("code", "")
    filename = data.get("filename", "code.py")
    findings = analyze_source(code, filename)
    findings.sort(key=lambda f: SEVERITY_RANK.get(f.severity, 99))
    return jsonify({
        "total":    len(findings),
        "findings": [
            {"rule_id": f.rule_id, "cwe": f.cwe, "severity": f.severity,
             "line": f.line, "col": f.col, "title": f.title,
             "detail": f.detail, "fix": f.fix, "filename": f.filename}
            for f in findings
        ]
    })


if __name__ == "__main__":
    print("\n  SAST Scanner — Web UI")
    print("  Open: http://localhost:5000\n")
    app.run(debug=False, port=5000)
