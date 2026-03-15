"""
Generador de dashboard HTML estilo HackerOne.
Dark theme, findings por severidad, timeline, filtros interactivos.
"""
import json
import os
from datetime import datetime
from pathlib import Path
from modules.core.logger import console, get_logger
from modules.core.storage import Storage

log = get_logger("reporting.dashboard")

# Placeholders únicos — no colisionan con CSS ni JS
_T   = "__PENTEST_TARGET__"
_S   = "__PENTEST_STARTED__"
_F   = "__PENTEST_FINISHED__"
_TOT = "__PENTEST_TOTAL__"
_CR  = "__PENTEST_CRITICAL__"
_HI  = "__PENTEST_HIGH__"
_ME  = "__PENTEST_MEDIUM__"
_LO  = "__PENTEST_LOW__"
_IN  = "__PENTEST_INFO__"
_DAT = "__PENTEST_DATA_JSON__"

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OrionRecon Report — """ + _T + """</title>
<style>
:root {
  --bg-primary:   #0d1117;
  --bg-secondary: #161b22;
  --bg-card:      #1c2128;
  --bg-hover:     #22272e;
  --border:       #30363d;
  --text-primary: #e6edf3;
  --text-sec:     #8b949e;
  --text-muted:   #484f58;
  --accent:       #388bfd;
  --critical:     #ff4d4f;
  --high:         #f97316;
  --medium:       #facc15;
  --low:          #60a5fa;
  --info-c:       #4ade80;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: var(--bg-primary);
  color: var(--text-primary);
  font-size: 14px;
  line-height: 1.5;
}
.layout { display: flex; min-height: 100vh; }
.sidebar {
  width: 250px;
  background: var(--bg-secondary);
  border-right: 1px solid var(--border);
  padding: 20px 0;
  position: fixed;
  top: 0; left: 0; bottom: 0;
  overflow-y: auto;
  z-index: 100;
}
.main { margin-left: 250px; padding: 28px; max-width: 1300px; }
.logo { padding: 0 20px 20px; border-bottom: 1px solid var(--border); margin-bottom: 12px; }
.logo h1 { font-size: 17px; font-weight: 700; color: var(--accent); }
.logo .tgt { font-size: 12px; color: var(--text-sec); margin-top: 4px; word-break: break-all; }
.nav-section { padding: 10px 20px 4px; font-size: 11px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.8px; color: var(--text-muted); margin-top: 6px; }
.sidebar a {
  display: flex; align-items: center; gap: 8px;
  padding: 8px 20px; color: var(--text-sec);
  text-decoration: none; font-size: 13px; transition: all 0.15s;
}
.sidebar a:hover, .sidebar a.active {
  background: var(--bg-hover); color: var(--text-primary);
  border-right: 2px solid var(--accent);
}
.card {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 8px; padding: 20px; margin-bottom: 20px;
}
.card-title { font-size: 15px; font-weight: 600; margin-bottom: 14px; }
.stat-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 14px; margin-bottom: 22px;
}
.stat {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 8px; padding: 16px; text-align: center;
}
.stat-val { font-size: 30px; font-weight: 700; line-height: 1; margin-bottom: 4px; }
.stat-lbl { font-size: 11px; color: var(--text-sec); text-transform: uppercase; letter-spacing: 0.5px; }
.c-total    { color: var(--accent); }
.c-critical { color: var(--critical); }
.c-high     { color: var(--high); }
.c-medium   { color: var(--medium); }
.c-low      { color: var(--low); }
.c-info     { color: var(--info-c); }
.badge {
  display: inline-flex; align-items: center;
  padding: 2px 10px; border-radius: 12px;
  font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px;
}
.badge-critical { background: rgba(255,77,79,.15);  color: var(--critical); border: 1px solid rgba(255,77,79,.3); }
.badge-high     { background: rgba(249,115,22,.15); color: var(--high);     border: 1px solid rgba(249,115,22,.3); }
.badge-medium   { background: rgba(250,204,21,.15); color: var(--medium);   border: 1px solid rgba(250,204,21,.3); }
.badge-low      { background: rgba(96,165,250,.15); color: var(--low);      border: 1px solid rgba(96,165,250,.3); }
.badge-info     { background: rgba(74,222,128,.15); color: var(--info-c);   border: 1px solid rgba(74,222,128,.3); }
.sev-bar { display: flex; gap: 3px; height: 8px; border-radius: 4px; overflow: hidden; margin-bottom: 6px; }
.sev-seg { height: 100%; }
.filters { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; align-items: center; }
.fbtn {
  padding: 4px 14px; border-radius: 20px; border: 1px solid var(--border);
  background: transparent; color: var(--text-sec); cursor: pointer;
  font-size: 12px; font-weight: 600; transition: all 0.15s;
}
.fbtn:hover { background: var(--bg-hover); color: var(--text-primary); border-color: var(--accent); }
.fbtn.fa { border-color: var(--accent); color: var(--text-primary); background: var(--bg-hover); }
.fbtn.fc { border-color: var(--critical); color: var(--critical); background: rgba(255,77,79,.08); }
.fbtn.fh { border-color: var(--high);     color: var(--high);     background: rgba(249,115,22,.08); }
.fbtn.fm { border-color: var(--medium);   color: var(--medium);   background: rgba(250,204,21,.08); }
.fbtn.fl { border-color: var(--low);      color: var(--low);      background: rgba(96,165,250,.08); }
.fbtn.fi { border-color: var(--info-c);   color: var(--info-c);   background: rgba(74,222,128,.08); }
.search-box {
  padding: 5px 12px; background: var(--bg-secondary); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text-primary); font-size: 13px; width: 230px; outline: none;
  margin-left: auto;
}
.search-box:focus { border-color: var(--accent); }
table { width: 100%; border-collapse: collapse; }
th {
  text-align: left; padding: 9px 14px; font-size: 11px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.4px; color: var(--text-sec);
  border-bottom: 1px solid var(--border); background: var(--bg-secondary);
}
td { padding: 11px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }
tr:last-child td { border-bottom: none; }
tr.frow:hover td { background: var(--bg-hover); cursor: pointer; }
.ftitle { font-weight: 500; margin-bottom: 3px; }
.fhost { font-size: 12px; color: var(--text-sec); font-family: monospace; }
.fmod {
  display: inline-flex; padding: 2px 7px; background: var(--bg-secondary);
  border: 1px solid var(--border); border-radius: 4px; font-size: 11px;
  color: var(--text-sec); font-family: monospace;
}
.detail-row { display: none; }
.detail-row.open { display: table-row; }
.detail-content { padding: 14px 18px; background: var(--bg-secondary); border-bottom: 1px solid var(--border); }
.dgrid { display: grid; grid-template-columns: 110px 1fr; gap: 7px 14px; font-size: 13px; }
.dlbl { color: var(--text-sec); font-weight: 600; }
.dval { color: var(--text-primary); word-break: break-all; }
.evidence {
  background: var(--bg-primary); border: 1px solid var(--border);
  border-radius: 6px; padding: 10px; font-family: monospace; font-size: 12px;
  white-space: pre-wrap; word-break: break-all; max-height: 180px; overflow-y: auto;
  color: var(--text-sec); margin-top: 8px;
}
.tag {
  display: inline-flex; padding: 1px 7px; background: var(--bg-secondary);
  border: 1px solid var(--border); border-radius: 10px;
  font-size: 11px; color: var(--text-sec); margin: 1px;
}
.ph { display: flex; align-items: center; justify-content: space-between; margin-bottom: 22px;
  padding-bottom: 18px; border-bottom: 1px solid var(--border); }
.pt { font-size: 21px; font-weight: 700; margin-bottom: 3px; }
.pm { font-size: 13px; color: var(--text-sec); }
.btn {
  padding: 7px 15px; border-radius: 6px; border: 1px solid var(--border);
  background: var(--bg-secondary); color: var(--text-primary); cursor: pointer;
  font-size: 13px; font-weight: 500; transition: all 0.15s; text-decoration: none;
  display: inline-flex; align-items: center; gap: 5px;
}
.btn:hover { background: var(--bg-hover); border-color: var(--accent); }
.btn-p { background: var(--accent); border-color: var(--accent); color: white; }
.btn-p:hover { opacity: 0.85; }
.empty { text-align: center; padding: 36px; color: var(--text-muted); font-size: 14px; }
section { display: none; }
section.active { display: block; }
.mod-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 10px; }
.mod-card {
  background: var(--bg-secondary); border: 1px solid var(--border);
  border-radius: 7px; padding: 13px;
}
.mod-name { font-size: 13px; font-weight: 600; color: var(--accent); margin-bottom: 4px; }
.mod-time { font-size: 11px; color: var(--text-muted); }
.tl { position: relative; padding-left: 18px; }
.tl::before { content:''; position:absolute; left:6px; top:8px; bottom:8px; width:2px; background:var(--border); }
.tl-item { position: relative; margin-bottom: 14px; }
.tl-dot { position:absolute; left:-13px; top:4px; width:10px; height:10px; border-radius:50%; background:var(--accent); border:2px solid var(--bg-primary); }
.tl-time { font-size:11px; color:var(--text-muted); margin-bottom:2px; font-family:monospace; }
.tl-text { font-size:13px; }
::-webkit-scrollbar { width:5px; height:5px; }
::-webkit-scrollbar-track { background:var(--bg-primary); }
::-webkit-scrollbar-thumb { background:var(--border); border-radius:3px; }
@media(max-width:768px) { .sidebar{display:none;} .main{margin-left:0;} }
</style>
</head>
<body>
<div class="layout">
<nav class="sidebar">
  <div class="logo">
    <h1>⭐ OrionRecon</h1>
    <div style="font-size:11px;color:var(--text-muted);margin-top:2px">Attack Surface Recon Toolkit</div>
    <div style="font-size:11px;color:var(--text-muted)">By Jorge RC</div>
    <div class="tgt" style="margin-top:6px">""" + _T + """</div>
  </div>
  <div class="nav-section">Navegación</div>
  <a href="#" onclick="nav('overview')"  id="n-overview"  class="active">🏠 Overview</a>
  <a href="#" onclick="nav('findings')"  id="n-findings">🔍 Findings (""" + _TOT + """)</a>
  <a href="#" onclick="nav('recon')"     id="n-recon">🌐 Recon / OSINT</a>
  <a href="#" onclick="nav('scanning')"  id="n-scanning">🔫 Nmap Artillery</a>
  <a href="#" onclick="nav('tech')"      id="n-tech">🔬 Tech Detection</a>
  <a href="#" onclick="nav('takeover')"  id="n-takeover">🎯 Takeover</a>
  <a href="#" onclick="nav('fuzzing')"   id="n-fuzzing">💥 Fuzzing</a>
  <a href="#" onclick="nav('timeline')"  id="n-timeline">📅 Timeline</a>
  <div class="nav-section">Export</div>
  <a href="#" onclick="exportJSON()">⬇ Export JSON</a>
</nav>

<main class="main">

<!-- OVERVIEW -->
<section id="s-overview" class="active">
  <div class="ph">
    <div>
      <div class="pt">Security Assessment Report</div>
      <div class="pm">
        Target: <strong>""" + _T + """</strong> &nbsp;|&nbsp;
        """ + _S + """ → """ + _F + """
      </div>
    </div>
    <button class="btn btn-p" onclick="exportJSON()">⬇ Export JSON</button>
  </div>
  <div class="stat-grid">
    <div class="stat"><div class="stat-val c-total">""" + _TOT + """</div><div class="stat-lbl">Total</div></div>
    <div class="stat"><div class="stat-val c-critical">""" + _CR + """</div><div class="stat-lbl">Critical</div></div>
    <div class="stat"><div class="stat-val c-high">""" + _HI + """</div><div class="stat-lbl">High</div></div>
    <div class="stat"><div class="stat-val c-medium">""" + _ME + """</div><div class="stat-lbl">Medium</div></div>
    <div class="stat"><div class="stat-val c-low">""" + _LO + """</div><div class="stat-lbl">Low</div></div>
    <div class="stat"><div class="stat-val c-info">""" + _IN + """</div><div class="stat-lbl">Info</div></div>
  </div>
  <div class="card">
    <div class="card-title">Distribución por severidad</div>
    <div class="sev-bar" id="sev-bar"></div>
    <div style="display:flex;gap:14px;font-size:12px;color:var(--text-sec);margin-top:6px">
      <span style="color:var(--critical)">● Critical</span>
      <span style="color:var(--high)">● High</span>
      <span style="color:var(--medium)">● Medium</span>
      <span style="color:var(--low)">● Low</span>
      <span style="color:var(--info-c)">● Info</span>
    </div>
  </div>
  <div class="card">
    <div class="card-title">Módulos ejecutados</div>
    <div class="mod-grid" id="mod-grid"></div>
  </div>
  <div class="card" style="padding:0;overflow:hidden">
    <div style="padding:16px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between">
      <div class="card-title" style="margin:0">Findings críticos y altos</div>
      <a href="#" onclick="nav('findings')" class="btn" style="font-size:12px">Ver todos →</a>
    </div>
    <table><thead><tr><th>Sev</th><th>Título</th><th>Host</th><th>Módulo</th></tr></thead>
    <tbody id="top-body"></tbody></table>
  </div>
</section>

<!-- FINDINGS -->
<section id="s-findings">
  <div class="ph">
    <div><div class="pt">All Findings</div>
    <div class="pm">""" + _TOT + """ vulnerabilidades encontradas</div></div>
  </div>
  <div class="filters">
    <button class="fbtn fa" onclick="setFilter('all',this)">All</button>
    <button class="fbtn" onclick="setFilter('critical',this)">🔴 Critical</button>
    <button class="fbtn" onclick="setFilter('high',this)">🟠 High</button>
    <button class="fbtn" onclick="setFilter('medium',this)">🟡 Medium</button>
    <button class="fbtn" onclick="setFilter('low',this)">🔵 Low</button>
    <button class="fbtn" onclick="setFilter('info',this)">🟢 Info</button>
    <input class="search-box" type="text" placeholder="🔍 Buscar..." oninput="setSearch(this.value)">
  </div>
  <div class="card" style="padding:0;overflow:hidden">
    <table><thead><tr>
      <th style="width:95px">Severidad</th><th>Título</th>
      <th style="width:190px">Host</th><th style="width:95px">Módulo</th>
      <th style="width:100px">Fecha</th>
    </tr></thead>
    <tbody id="findings-body"></tbody></table>
  </div>
</section>

<!-- RECON -->
<section id="s-recon">
  <div class="ph"><div class="pt">Recon / OSINT</div></div>
  <div id="recon-content"><div class="empty card">Sin datos de recon</div></div>
</section>

<!-- SCANNING -->
<section id="s-scanning">
  <div class="ph"><div class="pt">Nmap Artillery</div></div>
  <div id="scanning-content"><div class="empty card">Sin datos de nmap</div></div>
</section>

<!-- TECH -->
<section id="s-tech">
  <div class="ph"><div class="pt">Technology Detection</div></div>
  <div id="tech-content"><div class="empty card">Sin datos de tech detection</div></div>
</section>

<!-- TAKEOVER -->
<section id="s-takeover">
  <div class="ph"><div class="pt">Subdomain Takeover</div></div>
  <div id="takeover-content"><div class="empty card">Sin datos de takeover</div></div>
</section>

<!-- FUZZING -->
<section id="s-fuzzing">
  <div class="ph"><div class="pt">Fuzzing (ffuf)</div></div>
  <div id="fuzzing-content"><div class="empty card">Sin datos de fuzzing</div></div>
</section>

<!-- TIMELINE -->
<section id="s-timeline">
  <div class="ph"><div class="pt">Timeline</div></div>
  <div class="card"><div class="tl" id="tl-content"></div></div>
</section>

</main>
</div>

<footer style="
  margin-left:250px;
  border-top:1px solid var(--border);
  background:var(--bg-secondary);
  padding:16px 28px;
  display:flex;
  align-items:center;
  justify-content:space-between;
  font-size:12px;
  color:var(--text-muted);
">
  <div style="display:flex;align-items:center;gap:10px">
    <span style="font-size:16px">⭐</span>
    <div>
      <span style="color:var(--text-primary);font-weight:600">OrionRecon</span>
      <span style="margin:0 6px">·</span>
      <span>Attack Surface Recon Toolkit</span>
    </div>
  </div>
  <div style="display:flex;align-items:center;gap:18px">
    <span>By <strong style="color:var(--text-sec)">Jorge RC</strong></span>
    <span style="color:var(--border)">|</span>
    <span>Generado: """ + _S + """</span>
    <span style="color:var(--border)">|</span>
    <span style="color:var(--accent)">v1.0</span>
  </div>
</footer>

<script>
// ── DATA ──────────────────────────────────────────────────────
const DATA = """ + _DAT + """;

// ── NAV ───────────────────────────────────────────────────────
function nav(name) {
  document.querySelectorAll('section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.sidebar a').forEach(a => a.classList.remove('active'));
  document.getElementById('s-' + name).classList.add('active');
  const n = document.getElementById('n-' + name);
  if (n) n.classList.add('active');
  return false;
}

// ── UTILS ─────────────────────────────────────────────────────
function esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
const SEV_CLR = {critical:'var(--critical)',high:'var(--high)',medium:'var(--medium)',low:'var(--low)',info:'var(--info-c)'};
function badge(s) {
  s = (s||'info').toLowerCase();
  return `<span class="badge badge-${s}">${s}</span>`;
}

// ── OVERVIEW ──────────────────────────────────────────────────
function initOverview() {
  const findings = DATA.findings || [];
  const total = findings.length;
  const cnt = {critical:0,high:0,medium:0,low:0,info:0};
  findings.forEach(f => { if (cnt[f.severity] !== undefined) cnt[f.severity]++; });

  // Severity bar
  const bar = document.getElementById('sev-bar');
  if (total > 0) {
    Object.entries(cnt).forEach(([sev, n]) => {
      if (!n) return;
      const d = document.createElement('div');
      d.className = 'sev-seg';
      d.style.width = (n / total * 100) + '%';
      d.style.background = SEV_CLR[sev];
      d.title = sev + ': ' + n;
      bar.appendChild(d);
    });
  } else {
    bar.style.background = 'var(--border)';
  }

  // Modules
  const grid = document.getElementById('mod-grid');
  const icons = {recon:'🌐',nmap:'🔫',nuclei:'💊',tech_detection:'🔬',takeover:'🎯',fuzzing:'💥'};
  Object.entries(DATA.modules || {}).forEach(([name, data]) => {
    const d = document.createElement('div');
    d.className = 'mod-card';
    d.innerHTML = `<div class="mod-name">${icons[name]||'⚙'} ${esc(name)}</div>
      <div class="mod-time">${new Date(data.timestamp).toLocaleTimeString()}</div>`;
    grid.appendChild(d);
  });

  // Top findings
  const top = findings.filter(f => f.severity==='critical'||f.severity==='high').slice(0,10);
  const tb = document.getElementById('top-body');
  if (!top.length) {
    tb.innerHTML = '<tr><td colspan="4" class="empty">Sin findings críticos/altos</td></tr>';
  } else {
    top.forEach(f => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${badge(f.severity)}</td>
        <td><div class="ftitle">${esc(f.title)}</div></td>
        <td><div class="fhost">${esc(f.host)}</div></td>
        <td><span class="fmod">${esc(f.module)}</span></td>`;
      tb.appendChild(tr);
    });
  }
}

// ── FINDINGS ──────────────────────────────────────────────────
let curFilter = 'all', curSearch = '';

function renderFindings() {
  const findings = DATA.findings || [];
  const tbody = document.getElementById('findings-body');
  tbody.innerHTML = '';

  const list = findings.filter(f => {
    const mf = curFilter === 'all' || f.severity === curFilter;
    const ms = !curSearch || f.title.toLowerCase().includes(curSearch)
            || (f.host||'').toLowerCase().includes(curSearch)
            || (f.description||'').toLowerCase().includes(curSearch);
    return mf && ms;
  });

  if (!list.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty">Sin resultados</td></tr>';
    return;
  }

  list.forEach((f, i) => {
    const tr = document.createElement('tr');
    tr.className = 'frow';
    tr.onclick = () => toggleDetail('fd-' + i);
    tr.innerHTML = `
      <td>${badge(f.severity)}</td>
      <td>
        <div class="ftitle">${esc(f.title)}</div>
        ${f.cve ? `<span class="tag">${esc(f.cve)}</span>` : ''}
        ${(f.tags||[]).slice(0,3).map(t=>`<span class="tag">${esc(t)}</span>`).join('')}
      </td>
      <td><div class="fhost">${esc(f.host)}</div></td>
      <td><span class="fmod">${esc(f.module)}</span></td>
      <td style="color:var(--text-muted);font-size:12px">${new Date(f.timestamp).toLocaleDateString()}</td>`;
    tbody.appendChild(tr);

    const td2 = document.createElement('tr');
    td2.className = 'detail-row';
    td2.id = 'fd-' + i;
    td2.innerHTML = `<td colspan="5"><div class="detail-content">
      <div class="dgrid">
        <span class="dlbl">Descripción</span><span class="dval">${esc(f.description||'—')}</span>
        ${f.url ? `<span class="dlbl">URL</span><span class="dval"><a href="${esc(f.url)}" target="_blank" style="color:var(--accent)">${esc(f.url)}</a></span>` : ''}
        ${f.cve ? `<span class="dlbl">CVE</span><span class="dval">${esc(f.cve)}</span>` : ''}
        <span class="dlbl">Módulo</span><span class="dval">${esc(f.module)}</span>
        <span class="dlbl">Timestamp</span><span class="dval">${esc(f.timestamp)}</span>
      </div>
      ${f.evidence ? `<div style="margin-top:10px"><div class="dlbl" style="margin-bottom:4px">Evidencia</div>
        <div class="evidence">${esc(f.evidence)}</div></div>` : ''}
    </div></td>`;
    tbody.appendChild(td2);
  });
}

function toggleDetail(id) {
  const r = document.getElementById(id);
  if (r) r.classList.toggle('open');
}

function setFilter(sev, btn) {
  curFilter = sev;
  document.querySelectorAll('.fbtn').forEach(b => b.className = 'fbtn');
  const map = {all:'fa',critical:'fc',high:'fh',medium:'fm',low:'fl',info:'fi'};
  btn.className = 'fbtn ' + (map[sev]||'fa');
  renderFindings();
}

function setSearch(v) { curSearch = v.toLowerCase(); renderFindings(); }

// ── RECON ─────────────────────────────────────────────────────
function initRecon() {
  const recon = ((DATA.modules.recon||{}).results)||{};
  const el = document.getElementById('recon-content');
  if (!recon.domain) return;

  const alive = recon.alive_hosts || [];
  const emails = recon.emails || [];
  const subs = recon.subdomains || [];

  let html = `<div class="stat-grid">
    <div class="stat"><div class="stat-val c-total">${subs.length}</div><div class="stat-lbl">Subdominios</div></div>
    <div class="stat"><div class="stat-val c-info">${alive.length}</div><div class="stat-lbl">Hosts Vivos</div></div>
    <div class="stat"><div class="stat-val c-medium">${emails.length}</div><div class="stat-lbl">Emails</div></div>
  </div>`;

  if (emails.length) {
    html += `<div class="card"><div class="card-title">Emails encontrados</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;margin-top:8px">
        ${emails.map(e=>`<span class="tag">${esc(e)}</span>`).join('')}
      </div></div>`;
  }

  if (alive.length) {
    html += `<div class="card" style="padding:0;overflow:hidden">
      <div style="padding:14px 18px;border-bottom:1px solid var(--border)"><div class="card-title" style="margin:0">Hosts vivos</div></div>
      <table><thead><tr><th>Host</th><th>IPs</th><th>CNAMEs</th></tr></thead><tbody>
        ${alive.slice(0,200).map(h=>`<tr>
          <td style="font-family:monospace">${esc(h.host)}</td>
          <td style="font-family:monospace;font-size:12px">${(h.ips||[]).join(', ')}</td>
          <td style="font-family:monospace;font-size:12px;color:var(--text-sec)">${(h.cnames||[]).join(' → ')}</td>
        </tr>`).join('')}
      </tbody></table></div>`;
  }
  el.innerHTML = html;
}

// ── SCANNING ──────────────────────────────────────────────────
function initScanning() {
  const nmap = ((DATA.modules.nmap||{}).results)||{};
  const el = document.getElementById('scanning-content');
  if (!Object.keys(nmap).length) return;

  let html = '';
  for (const [profile, hostResults] of Object.entries(nmap)) {
    html += `<div class="card"><div class="card-title">Perfil: ${esc(profile)}</div>`;
    for (const res of hostResults) {
      for (const h of (res.hosts||[])) {
        html += `<div style="margin-bottom:14px">
          <div style="font-weight:600;color:var(--accent);margin-bottom:7px">
            ${esc(h.ip)} ${h.os ? `<span style="color:var(--text-sec);font-size:12px">(${esc(h.os)})</span>` : ''}
          </div>
          <table style="font-size:12px">
            <thead><tr><th>Puerto</th><th>Proto</th><th>Servicio</th><th>Versión</th></tr></thead>
            <tbody>${(h.ports||[]).map(p=>`<tr>
              <td style="font-family:monospace">${esc(p.port)}</td>
              <td>${esc(p.protocol)}</td>
              <td><strong>${esc(p.service)}</strong></td>
              <td style="color:var(--text-sec)">${esc(p.version)}</td>
            </tr>`).join('')}</tbody>
          </table></div>`;
      }
    }
    html += '</div>';
  }
  el.innerHTML = html || '<div class="empty card">Sin datos</div>';
}

// ── TECH ──────────────────────────────────────────────────────
function initTech() {
  const tech = ((DATA.modules.tech_detection||{}).results)||{};
  const results = tech.results || [];
  const el = document.getElementById('tech-content');
  if (!results.length) return;

  let html = '';
  for (const r of results) {
    const techs = r.technologies || {};
    const byCat = {};
    for (const [name, info] of Object.entries(techs)) {
      if (!byCat[info.category]) byCat[info.category] = [];
      byCat[info.category].push({name, version: info.version});
    }
    html += `<div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <div class="card-title" style="margin:0">${esc(r.url)}</div>
        <span style="font-size:12px;color:var(--text-sec)">HTTP ${r.status_code}</span>
      </div>
      ${Object.keys(techs).length ? Object.entries(byCat).map(([cat,items])=>`
        <div style="margin-bottom:10px">
          <div style="font-size:11px;font-weight:600;text-transform:uppercase;color:var(--text-muted);margin-bottom:5px">${esc(cat)}</div>
          <div style="display:flex;flex-wrap:wrap;gap:5px">
            ${items.map(t=>`<span class="tag">${esc(t.name)}${t.version?` <span style="color:var(--text-muted)">${esc(t.version)}</span>`:''}</span>`).join('')}
          </div>
        </div>`).join('') : '<div style="color:var(--text-muted)">Sin tecnologías detectadas</div>'}
      ${r.missing_security_headers&&r.missing_security_headers.length ? `
        <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border)">
          <div style="font-size:12px;font-weight:600;color:var(--medium);margin-bottom:5px">⚠ Headers de seguridad faltantes</div>
          <div style="display:flex;flex-wrap:wrap;gap:4px">
            ${r.missing_security_headers.map(h=>`<span class="tag" style="color:var(--medium)">${esc(h)}</span>`).join('')}
          </div>
        </div>` : ''}
    </div>`;
  }
  el.innerHTML = html;
}

// ── TAKEOVER ──────────────────────────────────────────────────
function initTakeover() {
  const data = ((DATA.modules.takeover||{}).results)||{};
  const vulns = data.vulnerabilities || [];
  const el = document.getElementById('takeover-content');

  let html = `<div class="stat-grid">
    <div class="stat"><div class="stat-val c-total">${data.total_checked||0}</div><div class="stat-lbl">Comprobados</div></div>
    <div class="stat"><div class="stat-val ${vulns.length?'c-critical':'c-info'}">${vulns.length}</div><div class="stat-lbl">Vulnerables</div></div>
  </div>`;

  if (vulns.length) {
    html += `<div class="card" style="padding:0;overflow:hidden">
      <table><thead><tr><th>Sev</th><th>Subdominio</th><th>Servicio</th><th>CNAME</th><th>Razón</th></tr></thead>
      <tbody>${vulns.map(v=>`<tr>
        <td>${badge(v.severity)}</td>
        <td style="font-family:monospace">${esc(v.subdomain)}</td>
        <td>${esc(v.service||'Unknown')}</td>
        <td style="font-family:monospace;font-size:11px;color:var(--text-sec)">${(v.cnames||[]).join(' → ')}</td>
        <td style="font-size:12px;color:var(--text-sec)">${esc(v.reason)}</td>
      </tr>`).join('')}</tbody></table></div>`;
  } else {
    html += '<div class="card"><div class="empty">✓ Sin takeovers detectados</div></div>';
  }
  el.innerHTML = html;
}

// ── FUZZING ───────────────────────────────────────────────────
function initFuzzing() {
  const data = ((DATA.modules.fuzzing||{}).results)||{};
  const el = document.getElementById('fuzzing-content');
  if (!Object.keys(data).length) return;

  let html = '';
  for (const [target, modes] of Object.entries(data)) {
    html += `<div class="card"><div class="card-title">${esc(target)}</div>`;
    for (const [mode, res] of Object.entries(modes)) {
      const results = res.results || [];
      html += `<div style="margin-bottom:14px">
        <div style="font-size:12px;font-weight:600;text-transform:uppercase;color:var(--text-sec);margin-bottom:7px">
          ${esc(mode)} — ${results.length} resultados
        </div>
        ${results.length ? `<table style="font-size:12px">
          <thead><tr><th>URL</th><th>Status</th><th>Length</th></tr></thead>
          <tbody>${results.slice(0,100).map(r=>`<tr>
            <td style="font-family:monospace">
              <a href="${esc(r.url)}" target="_blank" style="color:var(--accent)">${esc(r.url)}</a>
            </td>
            <td><span class="badge badge-info">${r.status}</span></td>
            <td style="color:var(--text-sec)">${r.length}</td>
          </tr>`).join('')}</tbody>
        </table>` : '<div style="color:var(--text-muted);font-size:13px">Sin resultados</div>'}
      </div>`;
    }
    html += '</div>';
  }
  el.innerHTML = html || '<div class="empty card">Sin datos de fuzzing</div>';
}

// ── TIMELINE ──────────────────────────────────────────────────
function initTimeline() {
  const tl = document.getElementById('tl-content');
  let items = [];

  if (DATA.meta) {
    items.push({time: DATA.meta.started_at, text: `Sesión iniciada — <strong>${esc(DATA.meta.target)}</strong>`, color:'var(--accent)'});
  }
  Object.entries(DATA.modules||{}).forEach(([name, d]) => {
    items.push({time: d.timestamp, text: `Módulo completado: <strong>${esc(name)}</strong>`, color:'var(--info-c)'});
  });
  (DATA.findings||[]).filter(f=>f.severity==='critical'||f.severity==='high').forEach(f => {
    items.push({time: f.timestamp, text: badge(f.severity)+' '+esc(f.title), color: SEV_CLR[f.severity]});
  });
  if (DATA.meta && DATA.meta.finished_at) {
    items.push({time: DATA.meta.finished_at, text: 'Sesión finalizada', color:'var(--accent)'});
  }
  items.sort((a,b) => new Date(a.time) - new Date(b.time));

  tl.innerHTML = items.map(it=>`
    <div class="tl-item">
      <div class="tl-dot" style="background:${it.color}"></div>
      <div class="tl-time">${new Date(it.time).toLocaleString()}</div>
      <div class="tl-text">${it.text}</div>
    </div>`).join('') || '<div class="empty">Sin timeline disponible</div>';
}

// ── EXPORT ────────────────────────────────────────────────────
function exportJSON() {
  const blob = new Blob([JSON.stringify(DATA, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'pentest-' + (DATA.meta.target||'report').replace(/[^a-z0-9]/gi,'_') + '.json';
  a.click();
}

// ── INIT ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initOverview();
  renderFindings();
  initRecon();
  initScanning();
  initTech();
  initTakeover();
  initFuzzing();
  initTimeline();
});
</script>
</body>
</html>
"""


class DashboardGenerator:
    MODULE_NAME = "reporting"

    def __init__(self, config: dict, storage: Storage):
        self.config = config
        self.storage = storage

    def generate(self) -> str:
        """Genera el HTML del dashboard y lo guarda. Retorna la ruta."""
        data    = self.storage.data
        summary = self.storage.summary()
        meta    = data.get("meta", {})

        target      = meta.get("target", "Unknown")
        started_at  = meta.get("started_at", "N/A")
        finished_at = meta.get("finished_at", "N/A")

        data_json = json.dumps(data, default=str, ensure_ascii=False)

        substitutions = {
            _T:   target,
            _S:   started_at,
            _F:   finished_at,
            _TOT: str(summary["total"]),
            _CR:  str(summary["critical"]),
            _HI:  str(summary["high"]),
            _ME:  str(summary["medium"]),
            _LO:  str(summary["low"]),
            _IN:  str(summary["info"]),
            _DAT: data_json,
        }

        html = HTML_TEMPLATE
        for placeholder, value in substitutions.items():
            html = html.replace(placeholder, value)

        out_path = self.storage.session_path / "report.html"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html)

        console.print(f"\n[success]✓ Dashboard generado:[/] [bold]{out_path}[/]")
        return str(out_path)
