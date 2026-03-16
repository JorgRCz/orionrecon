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
.screenshot-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:14px; }
.screenshot-card {
  background:var(--bg-secondary); border:1px solid var(--border); border-radius:8px; overflow:hidden;
}
.screenshot-card img { width:100%; height:180px; object-fit:cover; display:block; }
.screenshot-url { padding:8px 10px; font-size:11px; font-family:monospace; color:var(--text-sec);
  white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
::-webkit-scrollbar { width:5px; height:5px; }
::-webkit-scrollbar-track { background:var(--bg-primary); }
::-webkit-scrollbar-thumb { background:var(--border); border-radius:3px; }
@media(max-width:768px) { .sidebar{display:none;} .main{margin-left:0;} }
@media print {
  .sidebar { display:none !important; }
  .main { margin-left:0 !important; max-width:100%; padding:16px; }
  footer { margin-left:0 !important; }
  section { display:block !important; page-break-inside:avoid; }
  .btn, .filters, .search-box, .fbtn { display:none !important; }
  .card { break-inside:avoid; border:1px solid #ccc; }
  body { background:#fff; color:#111; }
  a { color:#0057b8; }
}
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
  <a href="#" onclick="return nav('overview')"    id="n-overview"    class="active">🏠 Overview</a>
  <a href="#" onclick="return nav('findings')"    id="n-findings">🔍 Findings (""" + _TOT + """)</a>
  <a href="#" onclick="return nav('recon')"       id="n-recon">🌐 Recon / OSINT</a>
  <a href="#" onclick="return nav('scanning')"    id="n-scanning">🔫 Nmap Artillery</a>
  <a href="#" onclick="return nav('tech')"        id="n-tech">🔬 Tech Detection</a>
  <a href="#" onclick="return nav('waf')"         id="n-waf">🛡 WAF / CDN</a>
  <a href="#" onclick="return nav('cors')"        id="n-cors">🌐 CORS</a>
  <a href="#" onclick="return nav('tls')"         id="n-tls">🔒 TLS / SSL</a>
  <a href="#" onclick="return nav('takeover')"    id="n-takeover">🎯 Takeover</a>
  <a href="#" onclick="return nav('fuzzing')"     id="n-fuzzing">💥 Fuzzing</a>
  <a href="#" onclick="return nav('crawl')"       id="n-crawl">🕷️ Crawl</a>
  <a href="#" onclick="return nav('secrets')"     id="n-secrets">🔐 Secrets</a>
  <a href="#" onclick="return nav('screenshots')" id="n-screenshots">📸 Screenshots</a>
  <a href="#" onclick="return nav('cloud')"       id="n-cloud">☁️ Cloud</a>
  <a href="#" onclick="return nav('owasp')"       id="n-owasp">🔟 OWASP Top 10</a>
  <a href="#" onclick="return nav('timeline')"    id="n-timeline">📅 Timeline</a>
  <div class="nav-section">Export</div>
  <a href="#" onclick="exportJSON()">⬇ Export JSON</a>
  <a href="#" onclick="exportReconCSV()">📋 Export Recon CSV</a>
  <a href="#" onclick="window.print()">🖨 Print / PDF</a>
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
  <div class="card" id="waf-overview-card" style="display:none">
    <div class="card-title">🛡 WAF / CDN Detectado</div>
    <div id="waf-overview-content"></div>
  </div>
  <div class="card">
    <div class="card-title">Módulos ejecutados</div>
    <div class="mod-grid" id="mod-grid"></div>
  </div>
  <div class="card" style="padding:0;overflow:hidden">
    <div style="padding:16px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between">
      <div class="card-title" style="margin:0">Findings críticos y altos</div>
      <a href="#" onclick="return nav('findings')" class="btn" style="font-size:12px">Ver todos →</a>
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

<!-- WAF -->
<section id="s-waf">
  <div class="ph"><div class="pt">🛡 WAF / CDN Detection</div>
  <div class="pm">Detección de Web Application Firewalls y CDNs</div></div>
  <div id="waf-content"><div class="empty card">Sin datos de WAF detection</div></div>
</section>

<!-- CORS -->
<section id="s-cors">
  <div class="ph"><div class="pt">🌐 CORS Misconfigurations</div>
  <div class="pm">Cross-Origin Resource Sharing policy testing</div></div>
  <div id="cors-content"><div class="empty card">Sin datos de CORS scanner</div></div>
</section>

<!-- TLS -->
<section id="s-tls">
  <div class="ph"><div class="pt">🔒 TLS / SSL Analysis</div>
  <div class="pm">Protocolos débiles · Cipher suites · Vulnerabilidades (Heartbleed, POODLE, etc.)</div></div>
  <div id="tls-content"><div class="empty card">Sin datos de TLS/SSL</div></div>
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

<!-- CRAWL -->
<section id="s-crawl">
  <div class="ph"><div class="pt">🕷️ Web Crawl — Endpoints</div>
  <div class="pm">Endpoints descubiertos · Formularios · Parámetros interesantes</div></div>
  <div id="crawl-content"><div class="empty card">Sin datos de crawl</div></div>
</section>

<!-- SECRETS -->
<section id="s-secrets">
  <div class="ph"><div class="pt">🔐 Secrets & Exposure</div>
  <div class="pm">API keys · Tokens · Passwords hardcodeadas · Private keys</div></div>
  <div id="secrets-content"><div class="empty card">Sin datos de secrets scanner</div></div>
</section>

<!-- SCREENSHOTS -->
<section id="s-screenshots">
  <div class="ph"><div class="pt">📸 Screenshots</div>
  <div class="pm">Capturas visuales de URLs objetivo</div></div>
  <div id="screenshots-content"><div class="empty card">Sin screenshots disponibles</div></div>
</section>

<!-- CLOUD -->
<section id="s-cloud">
  <div class="ph"><div class="pt">☁️ Cloud Infrastructure</div>
  <div class="pm">AWS S3 · GCP GCS · Azure Blob · DigitalOcean Spaces · DNS Cloud Detection</div></div>
  <div id="cloud-content"><div class="empty card">Sin datos de cloud scan</div></div>
</section>

<!-- OWASP TOP 10 -->
<section id="s-owasp">
  <div class="ph">
    <div><div class="pt">🔟 OWASP Top 10 — 2021</div>
    <div class="pm">Mapa de cobertura · Findings clasificados por categoría OWASP</div></div>
  </div>
  <div id="owasp-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px;margin-bottom:22px"></div>
  <div id="owasp-detail"></div>
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

  // WAF overview
  const wafData = ((DATA.modules.waf||{}).results)||{};
  const wafResults = wafData.results || {};
  const detectedWafs = Object.entries(wafResults).filter(([h,d]) => d.detected);
  if (detectedWafs.length) {
    document.getElementById('waf-overview-card').style.display = '';
    const el = document.getElementById('waf-overview-content');
    el.innerHTML = detectedWafs.map(([h,d]) => `
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <span class="badge badge-medium">${esc(d.confidence)}</span>
        <span style="font-family:monospace">${esc(h)}</span>
        <span style="color:var(--medium);font-weight:600">${esc(d.waf_name)}</span>
        <span style="font-size:11px;color:var(--text-muted)">(método: ${esc(d.method)})</span>
      </div>`).join('');
  }

  // Modules
  const grid = document.getElementById('mod-grid');
  const icons = {
    recon:'🌐', nmap:'🔫', nuclei:'💊', tech_detection:'🔬',
    takeover:'🎯', fuzzing:'💥', cloud:'☁️', waf:'🛡',
    cors:'🌐', tls_ssl:'🔒', secrets:'🔐', screenshots:'📸',
    crawl:'🕷️', httpx:'⚡', naabu:'🔍', shodan_recon:'👁',
  };
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
  const gau  = recon.gau || {};
  const asn  = recon.asn || {};

  let html = `<div class="stat-grid">
    <div class="stat"><div class="stat-val c-total">${subs.length}</div><div class="stat-lbl">Subdominios</div></div>
    <div class="stat"><div class="stat-val c-info">${alive.length}</div><div class="stat-lbl">Hosts Vivos</div></div>
    <div class="stat"><div class="stat-val c-medium">${emails.length}</div><div class="stat-lbl">Emails</div></div>
    <div class="stat"><div class="stat-val c-low">${gau.total||0}</div><div class="stat-lbl">URLs Hist.</div></div>
    <div class="stat"><div class="stat-val c-accent" style="color:var(--accent)">${(asn.cidrs||[]).length}</div><div class="stat-lbl">CIDRs ASN</div></div>
  </div>`;

  if (emails.length) {
    html += `<div class="card"><div class="card-title">Emails encontrados</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;margin-top:8px">
        ${emails.map(e=>`<span class="tag">${esc(e)}</span>`).join('')}
      </div></div>`;
  }

  if ((asn.cidrs||[]).length) {
    html += `<div class="card"><div class="card-title">ASN — Rangos IP</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px">
        ${(asn.asns||[]).map(a=>`<span class="tag" style="color:var(--accent)">${esc(a)}</span>`).join('')}
        ${(asn.cidrs||[]).map(c=>`<span class="tag" style="font-family:monospace">${esc(c)}</span>`).join('')}
      </div></div>`;
  }

  if ((gau.interesting||[]).length) {
    html += `<div class="card" style="padding:0;overflow:hidden">
      <div style="padding:14px 18px;border-bottom:1px solid var(--border)">
        <div class="card-title" style="margin:0">URLs históricas interesantes (GAU) — ${(gau.interesting||[]).length}</div>
      </div>
      <table style="font-size:12px"><thead><tr><th>URL</th><th>Razón</th></tr></thead><tbody>
        ${(gau.interesting||[]).slice(0,100).map(u=>`<tr>
          <td style="font-family:monospace"><a href="${esc(u.url)}" target="_blank" style="color:var(--accent)">${esc(u.url.slice(0,80))}</a></td>
          <td style="color:var(--text-sec)">${esc(u.reason)}</td>
        </tr>`).join('')}
      </tbody></table></div>`;
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

// ── WAF ───────────────────────────────────────────────────────
function initWaf() {
  const data = ((DATA.modules.waf||{}).results)||{};
  const results = data.results || {};
  const el = document.getElementById('waf-content');

  if (!Object.keys(results).length) return;

  const detected = Object.entries(results).filter(([h,d]) => d.detected);
  const clean    = Object.entries(results).filter(([h,d]) => !d.detected);

  let html = `<div class="stat-grid">
    <div class="stat"><div class="stat-val c-total">${Object.keys(results).length}</div><div class="stat-lbl">Analizados</div></div>
    <div class="stat"><div class="stat-val ${detected.length?'c-medium':'c-info'}">${detected.length}</div><div class="stat-lbl">WAF Detectado</div></div>
    <div class="stat"><div class="stat-val c-info">${clean.length}</div><div class="stat-lbl">Sin WAF</div></div>
  </div>`;

  if (detected.length) {
    html += `<div class="card" style="padding:0;overflow:hidden">
      <div style="padding:14px 18px;border-bottom:1px solid var(--border)"><div class="card-title" style="margin:0">WAFs / CDNs detectados</div></div>
      <table><thead><tr><th>Host</th><th>WAF / CDN</th><th>Confianza</th><th>Método</th><th>Evidencia</th></tr></thead>
      <tbody>${detected.map(([h,d])=>`<tr>
        <td style="font-family:monospace">${esc(h)}</td>
        <td><strong style="color:var(--medium)">${esc(d.waf_name)}</strong></td>
        <td><span class="badge badge-${d.confidence==='high'?'medium':'low'}">${esc(d.confidence)}</span></td>
        <td><span class="fmod">${esc(d.method)}</span></td>
        <td style="font-size:11px;color:var(--text-sec);font-family:monospace">${esc((d.evidence||'').slice(0,80))}</td>
      </tr>`).join('')}</tbody></table></div>`;
  } else {
    html += '<div class="card"><div class="empty">✓ No se detectaron WAFs en los targets analizados</div></div>';
  }

  el.innerHTML = html;
}

// ── CORS ──────────────────────────────────────────────────────
function initCors() {
  const data = ((DATA.modules.cors||{}).results)||{};
  const vulns = data.vulnerabilities || [];
  const el = document.getElementById('cors-content');

  let html = `<div class="stat-grid">
    <div class="stat"><div class="stat-val c-total">${data.total_tested||0}</div><div class="stat-lbl">Testeados</div></div>
    <div class="stat"><div class="stat-val ${vulns.length?'c-critical':'c-info'}">${vulns.length}</div><div class="stat-lbl">Vulnerables</div></div>
  </div>`;

  if (vulns.length) {
    html += `<div class="card" style="padding:0;overflow:hidden">
      <table><thead><tr><th>Sev</th><th>URL</th><th>Tipo</th><th>Origen enviado</th><th>ACAO recibido</th><th>Credentials</th></tr></thead>
      <tbody>${vulns.map(v=>`<tr>
        <td>${badge(v.severity)}</td>
        <td style="font-family:monospace;font-size:11px"><a href="${esc(v.url)}" target="_blank" style="color:var(--accent)">${esc(v.url.slice(0,60))}</a></td>
        <td><span class="fmod">${esc(v.type)}</span></td>
        <td style="font-family:monospace;font-size:11px;color:var(--text-sec)">${esc(v.origin_sent)}</td>
        <td style="font-family:monospace;font-size:11px;color:var(--medium)">${esc(v.acao)}</td>
        <td>${v.credentials ? '<span class="badge badge-critical">SI</span>' : '<span class="badge badge-info">No</span>'}</td>
      </tr>`).join('')}</tbody></table></div>`;
  } else {
    html += '<div class="card"><div class="empty">✓ Sin CORS misconfigurations detectadas</div></div>';
  }

  el.innerHTML = html;
}

// ── TLS ───────────────────────────────────────────────────────
function initTLS() {
  const data = ((DATA.modules.tls_ssl||{}).results)||{};
  const results = data.results || {};
  const el = document.getElementById('tls-content');

  if (!Object.keys(results).length) return;

  let html = '';
  for (const [target, res] of Object.entries(results)) {
    const weakProtos = res.weak_protocols || [];
    const vulns      = res.vulnerabilities || [];
    const issues     = res.issues || [];
    const certInfo   = res.cert_info || {};

    const sevColor = vulns.length ? 'var(--critical)' : weakProtos.length ? 'var(--medium)' : 'var(--info-c)';

    html += `<div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <div class="card-title" style="margin:0;font-family:monospace">${esc(target)}</div>
        <span class="fmod" style="color:var(--text-sec)">${esc(res.tool||'')}</span>
      </div>`;

    if (weakProtos.length) {
      html += `<div style="margin-bottom:10px">
        <div style="font-size:12px;font-weight:600;color:var(--medium);margin-bottom:5px">⚠ Protocolos débiles</div>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          ${weakProtos.map(p=>`<span class="badge badge-medium">${esc(p)}</span>`).join('')}
        </div></div>`;
    }

    if (vulns.length) {
      html += `<div style="margin-bottom:10px">
        <div style="font-size:12px;font-weight:600;color:var(--critical);margin-bottom:5px">🔴 Vulnerabilidades TLS</div>
        <table style="font-size:12px"><thead><tr><th>Vuln</th><th>Severidad</th><th>Detalle</th></tr></thead>
        <tbody>${vulns.map(v=>`<tr>
          <td><strong>${esc(v.name)}</strong></td>
          <td>${badge(v.severity||'high')}</td>
          <td style="color:var(--text-sec)">${esc(v.finding||'')}</td>
        </tr>`).join('')}</tbody></table></div>`;
    }

    if (Object.keys(certInfo).length) {
      html += `<div style="margin-top:8px;padding-top:8px;border-top:1px solid var(--border)">
        <div style="font-size:11px;font-weight:600;text-transform:uppercase;color:var(--text-muted);margin-bottom:5px">Certificado</div>
        <div style="font-size:12px;font-family:monospace;color:var(--text-sec)">
          ${Object.entries(certInfo).slice(0,4).map(([k,v])=>`<div><span style="color:var(--text-sec)">${esc(k)}:</span> ${esc(String(v).slice(0,100))}</div>`).join('')}
        </div></div>`;
    }

    if (!weakProtos.length && !vulns.length) {
      html += `<div style="color:var(--info-c);font-size:13px">✓ Sin problemas TLS detectados</div>`;
    }

    html += '</div>';
  }

  el.innerHTML = html || '<div class="empty card">Sin datos TLS/SSL</div>';
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
function statusColor(s) {
  if (s >= 200 && s < 300) return 'var(--info-c)';
  if (s >= 300 && s < 400) return 'var(--low)';
  if (s === 401 || s === 403) return 'var(--medium)';
  if (s >= 500) return 'var(--high)';
  return 'var(--text-sec)';
}

function fuzzFilter(id, status, btn) {
  const tbody = document.getElementById(id + '_body');
  if (!tbody) return;
  btn.closest('.fuzz-filters').querySelectorAll('.fbtn').forEach(b => {
    b.className = 'fbtn';
    b.style.cssText = '';
  });
  btn.className = 'fbtn fa';
  let visible = 0;
  tbody.querySelectorAll('tr').forEach(tr => {
    const show = status === 'all' || String(tr.dataset.status) === String(status);
    tr.style.display = show ? '' : 'none';
    if (show) visible++;
  });
  const cnt = document.getElementById(id + '_cnt');
  if (cnt) cnt.textContent = visible;
}

function initFuzzing() {
  const data = ((DATA.modules.fuzzing||{}).results)||{};
  const el = document.getElementById('fuzzing-content');
  if (!Object.keys(data).length) return;

  let html = '';
  let idx = 0;
  for (const [target, modes] of Object.entries(data)) {
    html += `<div class="card"><div class="card-title">${esc(target)}</div>`;
    for (const [mode, res] of Object.entries(modes)) {
      const results = res.results || [];
      const tblId = 'fuzz' + idx++;
      const statuses = [...new Set(results.map(r => r.status))].sort((a,b) => a-b);
      html += `<div style="margin-bottom:14px">
        <div style="font-size:12px;font-weight:600;text-transform:uppercase;color:var(--text-sec);margin-bottom:7px">
          ${esc(mode)} — <span id="${tblId}_cnt">${results.length}</span> resultados
        </div>
        ${results.length ? `
        <div class="filters fuzz-filters" style="margin-bottom:8px">
          <button class="fbtn fa" onclick="fuzzFilter('${tblId}','all',this)">All</button>
          ${statuses.map(s => `<button class="fbtn" onclick="fuzzFilter('${tblId}','${s}',this)"
            style="border-color:${statusColor(s)};color:${statusColor(s)}">${s}</button>`).join('')}
        </div>
        <table style="font-size:12px">
          <thead><tr><th>URL</th><th>Status</th><th>Length</th></tr></thead>
          <tbody id="${tblId}_body">
          ${results.slice(0,200).map(r=>`<tr data-status="${r.status}">
            <td style="font-family:monospace">
              <a href="${esc(r.url)}" target="_blank" style="color:var(--accent)">${esc(r.url)}</a>
            </td>
            <td><span class="badge" style="background:rgba(0,0,0,.2);color:${statusColor(r.status)};border-color:${statusColor(r.status)}">${r.status}</span></td>
            <td style="color:var(--text-sec)">${r.length}</td>
          </tr>`).join('')}
          </tbody>
        </table>` : '<div style="color:var(--text-muted);font-size:13px">Sin resultados</div>'}
      </div>`;
    }
    html += '</div>';
  }
  el.innerHTML = html || '<div class="empty card">Sin datos de fuzzing</div>';
}

// ── CRAWL ─────────────────────────────────────────────────────
function initCrawl() {
  const data = ((DATA.modules.crawl||{}).results)||{};
  const el = document.getElementById('crawl-content');
  const endpoints  = data.endpoints || [];
  const forms      = data.forms || [];
  const interesting = data.interesting_params || [];

  if (!endpoints.length && !forms.length) return;

  let html = `<div class="stat-grid">
    <div class="stat"><div class="stat-val c-total">${data.total||endpoints.length}</div><div class="stat-lbl">Endpoints</div></div>
    <div class="stat"><div class="stat-val c-medium">${interesting.length}</div><div class="stat-lbl">Params interesantes</div></div>
    <div class="stat"><div class="stat-val c-low">${forms.length}</div><div class="stat-lbl">Formularios</div></div>
  </div>`;

  if (interesting.length) {
    html += `<div class="card"><div class="card-title">Endpoints con parámetros interesantes</div>
      <table style="font-size:12px"><thead><tr><th>URL</th><th>Parámetros</th></tr></thead><tbody>
        ${interesting.slice(0,100).map(e=>`<tr>
          <td style="font-family:monospace"><a href="${esc(e.url)}" target="_blank" style="color:var(--accent)">${esc(e.url.slice(0,100))}</a></td>
          <td>${e.params.map(p=>`<span class="tag" style="color:var(--medium)">${esc(p)}</span>`).join('')}</td>
        </tr>`).join('')}
      </tbody></table></div>`;
  }

  if (endpoints.length) {
    html += `<div class="card" style="padding:0;overflow:hidden">
      <div style="padding:14px 18px;border-bottom:1px solid var(--border)">
        <div class="card-title" style="margin:0">Todos los endpoints (${endpoints.length})</div>
      </div>
      <table style="font-size:12px"><thead><tr><th>URL</th><th>Método</th><th>Fuente</th></tr></thead><tbody>
        ${endpoints.slice(0,300).map(e=>`<tr>
          <td style="font-family:monospace"><a href="${esc(e.url)}" target="_blank" style="color:var(--accent)">${esc(e.url.slice(0,100))}</a></td>
          <td><span class="fmod">${esc(e.method||'GET')}</span></td>
          <td style="font-size:11px;color:var(--text-sec)">${esc(e.source||'')}</td>
        </tr>`).join('')}
      </tbody></table></div>`;
  }

  el.innerHTML = html;
}

// ── SECRETS ───────────────────────────────────────────────────
function initSecrets() {
  const data = ((DATA.modules.secrets||{}).results)||{};
  const secrets = data.secrets || [];
  const el = document.getElementById('secrets-content');

  if (!secrets.length && !data.total) {
    el.innerHTML = '<div class="empty card">✓ Sin secrets detectados</div>';
    return;
  }

  const bySev = {critical:[],high:[],medium:[],low:[]};
  secrets.forEach(s => { if (bySev[s.severity]) bySev[s.severity].push(s); });

  let html = `<div class="stat-grid">
    <div class="stat"><div class="stat-val c-total">${data.total||secrets.length}</div><div class="stat-lbl">Total</div></div>
    <div class="stat"><div class="stat-val c-critical">${bySev.critical.length}</div><div class="stat-lbl">Critical</div></div>
    <div class="stat"><div class="stat-val c-high">${bySev.high.length}</div><div class="stat-lbl">High</div></div>
    <div class="stat"><div class="stat-val c-medium">${bySev.medium.length}</div><div class="stat-lbl">Medium</div></div>
  </div>`;

  if (secrets.length) {
    html += `<div class="card" style="padding:0;overflow:hidden">
      <table><thead><tr><th>Sev</th><th>Tipo</th><th>Host</th><th>Fuente</th><th>Valor (truncado)</th></tr></thead>
      <tbody>${secrets.map(s=>`<tr>
        <td>${badge(s.severity)}</td>
        <td><span class="fmod">${esc(s.type)}</span></td>
        <td style="font-family:monospace;font-size:11px">${esc(s.host)}</td>
        <td style="font-size:11px;color:var(--text-sec);font-family:monospace">
          ${s.source_url ? `<a href="${esc(s.source_url)}" target="_blank" style="color:var(--accent)">${esc(s.source_url.slice(0,50))}</a>` : ''}
        </td>
        <td style="font-family:monospace;font-size:11px;color:var(--text-muted)">${esc((s.value||'').slice(0,40))}…</td>
      </tr>`).join('')}</tbody></table></div>`;
  }

  el.innerHTML = html;
}

// ── SCREENSHOTS ───────────────────────────────────────────────
function initScreenshots() {
  const data = ((DATA.modules.screenshots||{}).results)||{};
  const screenshots = data.screenshots || [];
  const el = document.getElementById('screenshots-content');

  if (!screenshots.length) return;

  let html = `<div class="stat-grid">
    <div class="stat"><div class="stat-val c-total">${screenshots.length}</div><div class="stat-lbl">Screenshots</div></div>
  </div>
  <div class="screenshot-grid">
    ${screenshots.map(s=>`
      <div class="screenshot-card">
        <img src="${esc(s.screenshot_path)}" alt="${esc(s.url)}"
          onerror="this.style.display='none';this.nextSibling.style.display='flex'"
          loading="lazy">
        <div style="display:none;height:180px;align-items:center;justify-content:center;color:var(--text-muted);font-size:12px;background:var(--bg-primary)">
          No disponible
        </div>
        <div class="screenshot-url">${esc(s.url)}</div>
      </div>`).join('')}
  </div>`;

  el.innerHTML = html;
}

// ── OWASP TOP 10 ──────────────────────────────────────────────
const OWASP_CATS = [
  {id:'A01',title:'Broken Access Control',       icon:'🔓', desc:'IDOR, forced browsing, CORS, takeover, path traversal'},
  {id:'A02',title:'Cryptographic Failures',      icon:'🔐', desc:'TLS débil, HSTS ausente, datos sensibles en claro, cookies sin Secure'},
  {id:'A03',title:'Injection',                   icon:'💉', desc:'SQL Injection, XSS, Command Injection, LDAP injection'},
  {id:'A04',title:'Insecure Design',             icon:'📐', desc:'Flujos lógicos inseguros, falta de controles de seguridad en diseño'},
  {id:'A05',title:'Security Misconfiguration',   icon:'⚙️',  desc:'Headers ausentes, default credentials, error messages, cloud misconfiguration'},
  {id:'A06',title:'Vulnerable Components',       icon:'📦', desc:'Versiones con CVE conocidos, dependencias sin actualizar'},
  {id:'A07',title:'Auth Failures',               icon:'🔑', desc:'Default credentials, JWT inseguro, sesiones sin expiración'},
  {id:'A08',title:'Data Integrity Failures',     icon:'📋', desc:'Sin SRI, pipelines inseguros, deserialización insegura'},
  {id:'A09',title:'Logging & Monitoring',        icon:'📊', desc:'Sin logging, sin alertas, errores expuestos'},
  {id:'A10',title:'Server-Side Request Forgery', icon:'🌐', desc:'SSRF, redirecciones abiertas, fetch de recursos internos'},
];

// Mapeo: module / tag → OWASP IDs
const OWASP_MAP = {
  // by module
  cors:          ['A01'],
  takeover:      ['A01'],
  injection:     ['A03','A10','A01'],
  header_check:  ['A05','A02','A07'],
  auth_check:    ['A07','A05'],
  tls_ssl:       ['A02'],
  secrets:       ['A02','A07'],
  waf:           ['A05'],
  tech_detection:['A05','A06'],
  nuclei:        ['A03','A05','A06','A07'],
  cloud:         ['A01','A02','A05'],
  fuzzing:       ['A01','A05'],
  crawl:         ['A01'],
  // by tag
  'sql-injection':        ['A03'],
  'xss':                  ['A03'],
  'reflected-xss':        ['A03'],
  'ssrf':                 ['A10'],
  'path-traversal':       ['A01'],
  'lfi':                  ['A01'],
  'jwt':                  ['A07'],
  'default-credentials':  ['A07'],
  'cookie':               ['A02','A07'],
  'cors':                 ['A01'],
  'tls':                  ['A02'],
  'ssl':                  ['A02'],
  'hsts':                 ['A02'],
  'csp':                  ['A05','A03'],
  'headers':              ['A05'],
  'misconfiguration':     ['A05'],
  'disclosure':           ['A05'],
  'fingerprint':          ['A05'],
  'authentication':       ['A07'],
  'heartbleed':           ['A06'],
  'weak-protocol':        ['A02'],
};

function getOwaspIds(finding) {
  const ids = new Set();
  // by module
  (OWASP_MAP[finding.module] || []).forEach(id => ids.add(id));
  // by tags
  (finding.tags || []).forEach(tag => {
    (OWASP_MAP[tag] || []).forEach(id => ids.add(id));
  });
  return [...ids];
}

function initOWASP() {
  const findings = DATA.findings || [];

  // Agrupar findings por categoría OWASP
  const byCategory = {};
  OWASP_CATS.forEach(c => { byCategory[c.id] = []; });
  findings.forEach(f => {
    getOwaspIds(f).forEach(id => {
      if (byCategory[id]) byCategory[id].push(f);
    });
  });

  // También agregar datos de módulos OWASP específicos
  const headers  = ((DATA.modules.header_check||{}).results)||{};
  const inj      = ((DATA.modules.injection||{}).results)||{};
  const auth     = ((DATA.modules.auth_check||{}).results)||{};

  // Render grid de categorías
  const grid = document.getElementById('owasp-grid');
  grid.innerHTML = OWASP_CATS.map(cat => {
    const items = byCategory[cat.id] || [];
    const maxSev = items.reduce((acc, f) => {
      const order = {critical:4,high:3,medium:2,low:1,info:0};
      return (order[f.severity]||0) > (order[acc]||0) ? f.severity : acc;
    }, '');
    const borderColor = maxSev ? SEV_CLR[maxSev] : 'var(--border)';
    const countColor  = items.length ? (SEV_CLR[maxSev]||'var(--accent)') : 'var(--text-muted)';
    return `
    <div class="card" style="border-left:3px solid ${borderColor};cursor:pointer;transition:all 0.15s"
         onclick="showOwaspDetail('${cat.id}')" id="owasp-cat-${cat.id}">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px">
        <div>
          <span style="font-size:11px;font-weight:700;color:var(--text-muted);letter-spacing:0.5px">${cat.id}</span>
          <span style="font-size:11px;color:var(--text-muted);margin-left:4px">${cat.icon}</span>
        </div>
        <div style="font-size:22px;font-weight:700;color:${countColor}">${items.length}</div>
      </div>
      <div style="font-size:13px;font-weight:600;margin-bottom:3px">${cat.title}</div>
      <div style="font-size:11px;color:var(--text-muted);line-height:1.4">${cat.desc}</div>
      ${items.length ? `<div style="margin-top:8px;display:flex;gap:3px;flex-wrap:wrap">
        ${[...new Set(items.map(f=>f.severity))].map(s=>`<span class="badge badge-${s}" style="font-size:9px">${s}</span>`).join('')}
      </div>` : '<div style="margin-top:8px;font-size:11px;color:var(--info-c)">✓ Sin findings</div>'}
    </div>`;
  }).join('');

  // Render resumen de módulos OWASP en el detalle inicial
  const detail = document.getElementById('owasp-detail');
  let summaryHtml = '';

  // Header checker summary
  if (Object.keys(headers.results||{}).length) {
    const totalIssues = Object.values(headers.results).reduce((acc, r) =>
      acc + (r.missing_headers||[]).length + (r.cookie_issues||[]).length, 0);
    summaryHtml += `<div class="card">
      <div class="card-title">⚙️ A05 — Security Headers (${Object.keys(headers.results).length} URLs)</div>
      <div style="color:var(--text-sec);font-size:13px">${totalIssues} issues de headers detectados.</div>
    </div>`;
  }

  // Injection summary
  if (inj.total_tested) {
    summaryHtml += `<div class="card">
      <div class="card-title">💉 A03/A10 — Injection & SSRF</div>
      <div style="display:flex;gap:14px;font-size:13px">
        <span>SQLi: <strong style="color:${inj.sqli&&inj.sqli.length?'var(--critical)':'var(--info-c)'}">${(inj.sqli||[]).length}</strong></span>
        <span>XSS: <strong style="color:${inj.xss&&inj.xss.length?'var(--high)':'var(--info-c)'}">${(inj.xss||[]).length}</strong></span>
        <span>LFI: <strong style="color:${inj.lfi&&inj.lfi.length?'var(--critical)':'var(--info-c)'}">${(inj.lfi||[]).length}</strong></span>
        <span>SSRF params: <strong style="color:${inj.ssrf_params&&inj.ssrf_params.length?'var(--medium)':'var(--info-c)'}">${(inj.ssrf_params||[]).length}</strong></span>
      </div>
      <div style="font-size:11px;color:var(--text-muted);margin-top:6px">Testeadas ${inj.total_tested} URLs con parámetros</div>
    </div>`;
  }

  // Auth summary
  if (auth.total_tested) {
    summaryHtml += `<div class="card">
      <div class="card-title">🔑 A07 — Auth & Default Credentials</div>
      <div style="display:flex;gap:14px;font-size:13px">
        <span>Paneles abiertos: <strong style="color:${auth.open_panels&&auth.open_panels.length?'var(--high)':'var(--info-c)'}">${(auth.open_panels||[]).length}</strong></span>
        <span>Default creds: <strong style="color:${auth.default_creds&&auth.default_creds.length?'var(--critical)':'var(--info-c)'}">${(auth.default_creds||[]).length}</strong></span>
        <span>JWT issues: <strong style="color:${auth.jwt_issues&&auth.jwt_issues.length?'var(--high)':'var(--info-c)'}">${(auth.jwt_issues||[]).length}</strong></span>
      </div>
      <div style="font-size:11px;color:var(--text-muted);margin-top:6px">Hosts analizados: ${auth.total_tested}</div>
    </div>`;
  }

  if (summaryHtml) detail.innerHTML = summaryHtml;
}

function showOwaspDetail(catId) {
  const findings = DATA.findings || [];
  const byCategory = {};
  OWASP_CATS.forEach(c => { byCategory[c.id] = []; });
  findings.forEach(f => {
    getOwaspIds(f).forEach(id => { if (byCategory[id]) byCategory[id].push(f); });
  });

  const cat   = OWASP_CATS.find(c => c.id === catId);
  const items = byCategory[catId] || [];
  const detail = document.getElementById('owasp-detail');

  if (!cat) return;

  // Highlight selected card
  document.querySelectorAll('[id^="owasp-cat-"]').forEach(el => {
    el.style.background = '';
  });
  const card = document.getElementById('owasp-cat-' + catId);
  if (card) card.style.background = 'var(--bg-hover)';

  if (!items.length) {
    detail.innerHTML = `<div class="card"><div class="empty">✓ Sin findings para ${cat.id} — ${cat.title}</div></div>`;
    return;
  }

  const rows = items.map((f,i) => `<tr class="frow" onclick="toggleDetail('ofd-${catId}-${i}')">
    <td>${badge(f.severity)}</td>
    <td><div class="ftitle">${esc(f.title)}</div>
      ${(f.tags||[]).slice(0,3).map(t=>`<span class="tag">${esc(t)}</span>`).join('')}
    </td>
    <td><div class="fhost">${esc(f.host)}</div></td>
    <td><span class="fmod">${esc(f.module)}</span></td>
  </tr>
  <tr class="detail-row" id="ofd-${catId}-${i}"><td colspan="4"><div class="detail-content">
    <div class="dgrid">
      <span class="dlbl">Descripción</span><span class="dval">${esc(f.description||'—')}</span>
      ${f.url?`<span class="dlbl">URL</span><span class="dval"><a href="${esc(f.url)}" target="_blank" style="color:var(--accent)">${esc(f.url)}</a></span>`:''}
    </div>
    ${f.evidence?`<div style="margin-top:8px"><div class="dlbl" style="margin-bottom:4px">Evidencia</div><div class="evidence">${esc(f.evidence)}</div></div>`:''}
  </div></td></tr>`).join('');

  detail.innerHTML = `<div class="card" style="padding:0;overflow:hidden">
    <div style="padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px">
      <span style="font-size:16px">${cat.icon}</span>
      <div>
        <div class="card-title" style="margin:0">${cat.id} — ${cat.title}</div>
        <div style="font-size:11px;color:var(--text-muted)">${cat.desc}</div>
      </div>
      <span class="badge badge-${items[0]?.severity||'info'}" style="margin-left:auto">${items.length} finding${items.length!==1?'s':''}</span>
    </div>
    <table><thead><tr><th style="width:80px">Sev</th><th>Título</th><th style="width:160px">Host</th><th style="width:95px">Módulo</th></tr></thead>
    <tbody>${rows}</tbody></table>
  </div>`;
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

// ── CLOUD ─────────────────────────────────────────────────────
function initCloud() {
  const data = ((DATA.modules.cloud||{}).results)||{};
  const el = document.getElementById('cloud-content');
  if (!data.domain) return;

  const buckets = data.buckets || [];
  const cnames  = data.cname_detections || [];
  const publicBuckets = buckets.filter(b => b.public);

  let html = `<div class="stat-grid">
    <div class="stat"><div class="stat-val c-total">${buckets.length}</div><div class="stat-lbl">Buckets encontrados</div></div>
    <div class="stat"><div class="stat-val ${publicBuckets.length ? 'c-critical' : 'c-info'}">${publicBuckets.length}</div><div class="stat-lbl">Públicos</div></div>
    <div class="stat"><div class="stat-val c-medium">${cnames.length}</div><div class="stat-lbl">Servicios via DNS</div></div>
  </div>`;

  if (buckets.length) {
    html += `<div class="card" style="padding:0;overflow:hidden">
      <div style="padding:14px 18px;border-bottom:1px solid var(--border)">
        <div class="card-title" style="margin:0">Buckets / Storage</div>
      </div>
      <table><thead><tr><th>Servicio</th><th>Bucket</th><th>URL</th><th>Status</th><th>Público</th></tr></thead>
      <tbody>${buckets.map(b=>`<tr>
        <td><span class="fmod">${esc(b.service)}</span></td>
        <td style="font-family:monospace">${esc(b.bucket||'')}</td>
        <td style="font-family:monospace;font-size:12px">
          <a href="${esc(b.url)}" target="_blank" style="color:var(--accent)">${esc(b.url)}</a>
        </td>
        <td><span class="badge" style="color:${statusColor(b.status)};border-color:${statusColor(b.status)};background:rgba(0,0,0,.2)">${b.status}</span></td>
        <td>${b.public ? '<span class="badge badge-critical">SI</span>' : '<span class="badge badge-info">No</span>'}</td>
      </tr>`).join('')}</tbody></table></div>`;
  }

  if (cnames.length) {
    html += `<div class="card" style="padding:0;overflow:hidden">
      <div style="padding:14px 18px;border-bottom:1px solid var(--border)">
        <div class="card-title" style="margin:0">Servicios cloud detectados via CNAME</div>
      </div>
      <table><thead><tr><th>Host</th><th>Servicio</th><th>CNAME</th><th>IPs</th></tr></thead>
      <tbody>${cnames.map(c=>`<tr>
        <td style="font-family:monospace">${esc(c.host)}</td>
        <td><span class="fmod">${esc(c.service)}</span></td>
        <td style="font-family:monospace;font-size:12px;color:var(--text-sec)">${esc(c.cname)}</td>
        <td style="font-family:monospace;font-size:12px;color:var(--text-sec)">${(c.ips||[]).join(', ')}</td>
      </tr>`).join('')}</tbody></table></div>`;
  }

  if (!buckets.length && !cnames.length) {
    html += '<div class="card"><div class="empty">Sin activos cloud detectados para este target</div></div>';
  }

  el.innerHTML = html;
}

// ── EXPORT RECON CSV ──────────────────────────────────────────
function exportReconCSV() {
  const recon = ((DATA.modules.recon||{}).results)||{};
  const resolved = recon.resolved || [];
  const emails   = recon.emails || [];

  if (!resolved.length && !emails.length) {
    alert('Sin datos de recon para exportar.');
    return;
  }

  let hostsCSV = 'host,ips,cnames,alive\n';
  resolved.forEach(h => {
    const ips    = (h.ips||[]).join('|');
    const cnames = (h.cnames||[]).join('|');
    hostsCSV += `"${h.host}","${ips}","${cnames}",${h.alive}\n`;
  });

  const target = (DATA.meta||{}).target || 'report';
  const safe   = target.replace(/[^a-z0-9]/gi,'_');

  const blobHosts = new Blob([hostsCSV], {type:'text/csv'});
  const a1 = document.createElement('a');
  a1.href = URL.createObjectURL(blobHosts);
  a1.download = `recon_hosts_${safe}.csv`;
  a1.click();

  if (emails.length) {
    setTimeout(() => {
      const emailsCSV = 'email\n' + emails.map(e => `"${e}"`).join('\n');
      const blobEmails = new Blob([emailsCSV], {type:'text/csv'});
      const a2 = document.createElement('a');
      a2.href = URL.createObjectURL(blobEmails);
      a2.download = `recon_emails_${safe}.csv`;
      a2.click();
    }, 400);
  }
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
  initWaf();
  initCors();
  initTLS();
  initTakeover();
  initFuzzing();
  initCrawl();
  initSecrets();
  initScreenshots();
  initCloud();
  initOWASP();
  initTimeline();
});
</script>
</body>
</html>
"""


class DashboardGenerator:
    MODULE_NAME = "reporting"

    def __init__(self, config: dict, storage: Storage):
        self.config  = config
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
        # Evitar que valores con "</script>" rompan el tag <script> embebido
        data_json = data_json.replace("</", "<\\/")

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

    def generate_pdf(self) -> str | None:
        """Genera un PDF del reporte usando WeasyPrint con HTML estático pre-renderizado."""
        try:
            from weasyprint import HTML as WH, CSS
        except ImportError:
            log.warning(
                "WeasyPrint no instalado. Instala con: pip install weasyprint\n"
                "En Kali/Debian también necesitas: sudo apt install libpango-1.0-0 libpangoft2-1.0-0"
            )
            return None

        pdf_path = self.storage.session_path / "report.pdf"

        try:
            static_html = self._build_pdf_html()
            page_css = CSS(string="@page { size: A4; margin: 1.5cm; }")
            WH(string=static_html).write_pdf(str(pdf_path), stylesheets=[page_css])
            console.print(f"[success]✓ PDF generado:[/] [bold]{pdf_path}[/]")
            return str(pdf_path)
        except Exception as e:
            log.error(f"Error generando PDF: {e}")
            return None

    def _build_pdf_html(self) -> str:  # noqa: C901
        """Genera HTML estático (sin JS) con todo el contenido pre-renderizado para WeasyPrint."""
        import html as _h

        data     = self.storage.data
        summary  = self.storage.summary()
        meta     = data.get("meta", {})
        modules  = data.get("modules", {})
        findings = data.get("findings", [])

        target      = meta.get("target", "Unknown")
        started_at  = meta.get("started_at", "N/A")
        finished_at = meta.get("finished_at", "N/A")

        def esc(s):
            return _h.escape(str(s) if s is not None else "")

        sev_colors = {
            "critical": "#dc2626", "high": "#ea580c",
            "medium": "#b45309", "low": "#1d4ed8", "info": "#15803d",
        }

        def badge(sev):
            sev = (sev or "info").lower()
            c = sev_colors.get(sev, "#6b7280")
            return (f'<span style="background:{c};color:#fff;padding:2px 7px;'
                    f'border-radius:3px;font-size:10px;font-weight:700;'
                    f'text-transform:uppercase">{esc(sev)}</span>')

        sections = []

        # ── Cover / Summary ──────────────────────────────────────────
        sev_order = ["critical", "high", "medium", "low", "info"]
        stat_cells = "".join(
            f'<td style="text-align:center;padding:10px 8px;border:1px solid #ddd;border-radius:4px">'
            f'<div style="font-size:24px;font-weight:700;color:{sev_colors.get(s,"#333")}">'
            f'{summary.get(s,0)}</div>'
            f'<div style="font-size:10px;text-transform:uppercase;color:#666">{s}</div></td>'
            for s in sev_order
        )
        stat_cells = (
            f'<td style="text-align:center;padding:10px 8px;border:1px solid #ddd;border-radius:4px">'
            f'<div style="font-size:24px;font-weight:700;color:#1e3a5f">{summary.get("total",0)}</div>'
            f'<div style="font-size:10px;text-transform:uppercase;color:#666">Total</div></td>'
            + stat_cells
        )
        sections.append(f"""
<div class="section">
  <table style="width:100%;border-collapse:separate;border-spacing:6px;margin-bottom:16px">
    <tr>{stat_cells}</tr>
  </table>
</div>""")

        # ── Findings ─────────────────────────────────────────────────
        if findings:
            order_map = {s: i for i, s in enumerate(sev_order)}
            sorted_f = sorted(findings, key=lambda x: order_map.get((x.get("severity") or "info").lower(), 5))
            rows = "".join(
                f'<tr><td>{badge(f.get("severity","info"))}</td>'
                f'<td>{esc(f.get("title",""))}</td>'
                f'<td style="font-size:11px;font-family:monospace">{esc(f.get("host",""))}</td>'
                f'<td style="font-size:11px">{esc(f.get("module",""))}</td></tr>'
                for f in sorted_f
            )
            sections.append(f"""
<div class="section page-break">
  <h2>Findings ({len(findings)})</h2>
  <table class="dt">
    <thead><tr><th style="width:75px">Sev</th><th>Título</th>
    <th style="width:160px">Host</th><th style="width:90px">Módulo</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>""")

        # ── Recon ─────────────────────────────────────────────────────
        recon = (modules.get("recon") or {}).get("results") or {}
        if recon.get("domain"):
            alive  = recon.get("alive_hosts") or []
            emails = recon.get("emails") or []
            subs   = recon.get("subdomains") or []
            gau    = recon.get("gau") or {}
            asn    = recon.get("asn") or {}

            stats = (
                f'<td class="sb"><div class="sn" style="color:#1e3a5f">{len(subs)}</div>'
                f'<div class="sl">Subdominios</div></td>'
                f'<td class="sb"><div class="sn" style="color:#15803d">{len(alive)}</div>'
                f'<div class="sl">Hosts Vivos</div></td>'
                f'<td class="sb"><div class="sn" style="color:#b45309">{len(emails)}</div>'
                f'<div class="sl">Emails</div></td>'
                f'<td class="sb"><div class="sn" style="color:#1d4ed8">{gau.get("total",0)}</div>'
                f'<div class="sl">URLs Hist.</div></td>'
            )
            recon_html = f"""
<div class="section page-break">
  <h2>Recon / OSINT</h2>
  <table style="width:100%;border-collapse:separate;border-spacing:6px;margin-bottom:14px">
    <tr>{stats}</tr>
  </table>"""

            if emails:
                email_tags = " &nbsp; ".join(f'<code>{esc(e)}</code>' for e in emails)
                recon_html += f'<h3>Emails encontrados</h3><p style="font-size:11px;margin-bottom:10px">{email_tags}</p>'

            if (asn.get("cidrs") or []):
                asn_tags = " ".join(f'<code>{esc(c)}</code>' for c in (asn.get("cidrs") or []))
                asns_str = " ".join(esc(a) for a in (asn.get("asns") or []))
                recon_html += f'<h3>ASN — Rangos IP {asns_str}</h3><p style="font-size:11px;margin-bottom:10px">{asn_tags}</p>'

            if alive:
                rows = "".join(
                    f'<tr><td style="font-family:monospace">{esc(h.get("host",""))}</td>'
                    f'<td style="font-size:11px;font-family:monospace">{", ".join(esc(ip) for ip in (h.get("ips") or []))}</td>'
                    f'<td style="font-size:11px;color:#666;font-family:monospace">{" → ".join(esc(c) for c in (h.get("cnames") or []))}</td></tr>'
                    for h in alive[:150]
                )
                recon_html += f"""<h3>Hosts Vivos ({len(alive)})</h3>
  <table class="dt"><thead><tr><th>Host</th><th>IPs</th><th>CNAMEs</th></tr></thead>
  <tbody>{rows}</tbody></table>"""

            if (gau.get("interesting") or []):
                rows = "".join(
                    f'<tr><td style="font-family:monospace;font-size:10px">{esc((u.get("url") or "")[:90])}</td>'
                    f'<td style="font-size:11px;color:#666">{esc(u.get("reason",""))}</td></tr>'
                    for u in (gau.get("interesting") or [])[:50]
                )
                recon_html += f"""<h3>URLs históricas interesantes — GAU (top 50)</h3>
  <table class="dt"><thead><tr><th>URL</th><th>Razón</th></tr></thead>
  <tbody>{rows}</tbody></table>"""

            recon_html += "</div>"
            sections.append(recon_html)

        # ── Nmap ──────────────────────────────────────────────────────
        nmap = (modules.get("nmap") or {}).get("results") or {}
        if nmap:
            nmap_html = '<div class="section page-break"><h2>Nmap Artillery</h2>'
            for profile, host_results in nmap.items():
                nmap_html += f'<h3>Perfil: {esc(profile)}</h3>'
                for res in (host_results or []):
                    for h in (res.get("hosts") or []):
                        ports = h.get("ports") or []
                        if not ports:
                            continue
                        rows = "".join(
                            f'<tr><td style="font-family:monospace">{esc(p.get("port",""))}</td>'
                            f'<td>{esc(p.get("protocol",""))}</td>'
                            f'<td><strong>{esc(p.get("service",""))}</strong></td>'
                            f'<td style="color:#666">{esc(p.get("version",""))}</td></tr>'
                            for p in ports
                        )
                        os_str = f' <span style="color:#666;font-size:11px">({esc(h.get("os",""))})</span>' if h.get("os") else ""
                        nmap_html += (
                            f'<div style="margin-bottom:12px">'
                            f'<div style="font-weight:700;color:#1e3a5f;margin-bottom:5px">{esc(h.get("ip",""))}{os_str}</div>'
                            f'<table class="dt" style="font-size:11px"><thead><tr>'
                            f'<th>Puerto</th><th>Proto</th><th>Servicio</th><th>Versión</th></tr></thead>'
                            f'<tbody>{rows}</tbody></table></div>'
                        )
            nmap_html += "</div>"
            sections.append(nmap_html)

        # ── TLS/SSL ───────────────────────────────────────────────────
        tls_data = (modules.get("tls_ssl") or {}).get("results") or {}
        tls_results = tls_data.get("results") or {}
        if tls_results:
            tls_html = '<div class="section page-break"><h2>TLS / SSL</h2>'
            for tgt, res in tls_results.items():
                weak  = res.get("weak_protocols") or []
                vulns = res.get("vulnerabilities") or []
                cert  = res.get("cert_info") or {}
                tls_html += f'<div style="margin-bottom:14px;padding:10px;border:1px solid #ddd;border-radius:4px">'
                tls_html += f'<div style="font-family:monospace;font-weight:700;margin-bottom:6px">{esc(tgt)} <span style="font-size:10px;color:#999;font-weight:400">{esc(res.get("tool",""))}</span></div>'
                if weak:
                    tls_html += f'<div style="color:#b45309;margin-bottom:4px">⚠ Protocolos débiles: {", ".join(esc(p) for p in weak)}</div>'
                if vulns:
                    for v in vulns:
                        tls_html += f'<div style="color:#dc2626">🔴 {esc(v.get("name",""))}: {esc(v.get("finding",""))}</div>'
                if cert:
                    for k in ("subject", "issuer", "not_after", "not_before"):
                        if cert.get(k):
                            tls_html += f'<div style="font-size:11px;color:#666">{esc(k)}: {esc(str(cert[k])[:100])}</div>'
                if not weak and not vulns:
                    tls_html += '<div style="color:#15803d">✓ Sin problemas TLS detectados</div>'
                tls_html += '</div>'
            tls_html += "</div>"
            sections.append(tls_html)

        # ── WAF ───────────────────────────────────────────────────────
        waf_data = (modules.get("waf") or {}).get("results") or {}
        waf_results = waf_data.get("results") or {}
        detected_wafs = [(h, d) for h, d in waf_results.items() if d.get("detected")]
        if detected_wafs:
            rows = "".join(
                f'<tr><td style="font-family:monospace">{esc(h)}</td>'
                f'<td><strong style="color:#b45309">{esc(d.get("waf_name",""))}</strong></td>'
                f'<td>{esc(d.get("confidence",""))}</td>'
                f'<td style="font-size:11px;color:#666">{esc(d.get("method",""))}</td></tr>'
                for h, d in detected_wafs
            )
            sections.append(f"""
<div class="section page-break">
  <h2>WAF / CDN Detection ({len(detected_wafs)} detectados)</h2>
  <table class="dt"><thead><tr><th>Host</th><th>WAF / CDN</th><th>Confianza</th><th>Método</th></tr></thead>
  <tbody>{rows}</tbody></table>
</div>""")

        # ── CORS ──────────────────────────────────────────────────────
        cors_data = (modules.get("cors") or {}).get("results") or {}
        cors_vulns = cors_data.get("vulnerabilities") or []
        if cors_vulns:
            rows = "".join(
                f'<tr><td>{badge(v.get("severity","high"))}</td>'
                f'<td style="font-size:11px;font-family:monospace">{esc((v.get("url") or "")[:80])}</td>'
                f'<td>{esc(v.get("type",""))}</td>'
                f'<td>{"SI" if v.get("credentials") else "No"}</td></tr>'
                for v in cors_vulns
            )
            sections.append(f"""
<div class="section page-break">
  <h2>CORS Misconfigurations ({len(cors_vulns)})</h2>
  <table class="dt"><thead><tr><th>Sev</th><th>URL</th><th>Tipo</th><th>Credentials</th></tr></thead>
  <tbody>{rows}</tbody></table>
</div>""")

        # ── Takeover ─────────────────────────────────────────────────
        takeover = (modules.get("takeover") or {}).get("results") or {}
        vuln_t = takeover.get("vulnerabilities") or []
        if vuln_t:
            rows = "".join(
                f'<tr><td>{badge(v.get("severity","medium"))}</td>'
                f'<td style="font-family:monospace">{esc(v.get("subdomain",""))}</td>'
                f'<td>{esc(v.get("service",""))}</td>'
                f'<td style="font-size:11px;color:#666">{esc(v.get("reason",""))}</td></tr>'
                for v in vuln_t
            )
            sections.append(f"""
<div class="section page-break">
  <h2>Subdomain Takeover ({len(vuln_t)})</h2>
  <table class="dt"><thead><tr><th>Sev</th><th>Subdominio</th><th>Servicio</th><th>Razón</th></tr></thead>
  <tbody>{rows}</tbody></table>
</div>""")

        # ── Secrets ───────────────────────────────────────────────────
        secrets_data = (modules.get("secrets") or {}).get("results") or {}
        secrets_list = secrets_data.get("secrets") or []
        if secrets_list:
            rows = "".join(
                f'<tr><td>{badge(s.get("severity","high"))}</td>'
                f'<td>{esc(s.get("type",""))}</td>'
                f'<td style="font-family:monospace;font-size:11px">{esc(s.get("host",""))}</td>'
                f'<td style="font-family:monospace;font-size:10px;color:#666">'
                f'{esc((s.get("value") or "")[:40])}…</td></tr>'
                for s in secrets_list
            )
            sections.append(f"""
<div class="section page-break">
  <h2>Secrets &amp; Exposure ({len(secrets_list)})</h2>
  <table class="dt"><thead><tr><th>Sev</th><th>Tipo</th><th>Host</th><th>Valor (truncado)</th></tr></thead>
  <tbody>{rows}</tbody></table>
</div>""")

        # ── Cloud ─────────────────────────────────────────────────────
        cloud = (modules.get("cloud") or {}).get("results") or {}
        if cloud.get("domain"):
            buckets = cloud.get("buckets") or []
            cnames  = cloud.get("cname_detections") or []
            cloud_html = '<div class="section page-break"><h2>Cloud Infrastructure</h2>'
            if buckets:
                rows = "".join(
                    f'<tr><td>{esc(b.get("service",""))}</td>'
                    f'<td style="font-family:monospace;font-size:11px">{esc(b.get("bucket",""))}</td>'
                    f'<td style="font-size:10px;font-family:monospace">{esc((b.get("url") or "")[:60])}</td>'
                    f'<td>{esc(str(b.get("status","")))}</td>'
                    f'<td>{"✓ SÍ" if b.get("public") else "No"}</td></tr>'
                    for b in buckets
                )
                cloud_html += f"""<h3>Buckets / Storage ({len(buckets)})</h3>
  <table class="dt"><thead><tr><th>Servicio</th><th>Bucket</th><th>URL</th><th>Status</th><th>Público</th></tr></thead>
  <tbody>{rows}</tbody></table>"""
            if cnames:
                rows = "".join(
                    f'<tr><td style="font-family:monospace">{esc(c.get("host",""))}</td>'
                    f'<td>{esc(c.get("service",""))}</td>'
                    f'<td style="font-family:monospace;font-size:11px;color:#666">{esc(c.get("cname",""))}</td>'
                    f'<td style="font-size:11px;color:#666">{", ".join(esc(ip) for ip in (c.get("ips") or []))}</td></tr>'
                    for c in cnames
                )
                cloud_html += f"""<h3>Servicios cloud via CNAME ({len(cnames)})</h3>
  <table class="dt"><thead><tr><th>Host</th><th>Servicio</th><th>CNAME</th><th>IPs</th></tr></thead>
  <tbody>{rows}</tbody></table>"""
            if not buckets and not cnames:
                cloud_html += '<p style="color:#666">Sin activos cloud detectados.</p>'
            cloud_html += "</div>"
            sections.append(cloud_html)

        # ── Fuzzing ───────────────────────────────────────────────────
        fuzz_data = (modules.get("fuzzing") or {}).get("results") or {}
        if fuzz_data:
            fuzz_html = '<div class="section page-break"><h2>Fuzzing (ffuf)</h2>'
            for tgt, modes in fuzz_data.items():
                fuzz_html += f'<h3>{esc(tgt)}</h3>'
                for mode, res in (modes or {}).items():
                    results = (res.get("results") or [])
                    # Only include 2xx, 3xx, 4xx results (exclude 404/400)
                    notable = [r for r in results if r.get("status") not in (404, 400, 0)][:100]
                    if not notable:
                        continue
                    rows = "".join(
                        f'<tr><td style="font-family:monospace;font-size:10px">{esc(r.get("url",""))}</td>'
                        f'<td style="text-align:center">{esc(str(r.get("status","")))}</td>'
                        f'<td style="text-align:right;color:#666">{esc(str(r.get("length","")))}</td></tr>'
                        for r in notable
                    )
                    fuzz_html += f"""<div style="margin-bottom:10px">
  <div style="font-size:11px;font-weight:600;text-transform:uppercase;color:#666;margin-bottom:5px">{esc(mode)} — {len(notable)} resultados notables</div>
  <table class="dt" style="font-size:11px"><thead><tr><th>URL</th><th style="width:60px">Status</th><th style="width:70px">Length</th></tr></thead>
  <tbody>{rows}</tbody></table></div>"""
            fuzz_html += "</div>"
            sections.append(fuzz_html)

        # ── Crawl ─────────────────────────────────────────────────────
        crawl_data = (modules.get("crawl") or {}).get("results") or {}
        crawl_endpoints = crawl_data.get("endpoints") or []
        crawl_interesting = crawl_data.get("interesting_params") or []
        if crawl_interesting or crawl_endpoints:
            crawl_html = '<div class="section page-break"><h2>Web Crawl — Endpoints</h2>'
            if crawl_interesting:
                rows = "".join(
                    f'<tr><td style="font-family:monospace;font-size:10px">{esc((e.get("url") or "")[:90])}</td>'
                    f'<td style="font-size:11px">{" ".join(esc(p) for p in (e.get("params") or []))}</td></tr>'
                    for e in crawl_interesting[:80]
                )
                crawl_html += f"""<h3>Endpoints con parámetros interesantes ({len(crawl_interesting)})</h3>
  <table class="dt" style="font-size:11px"><thead><tr><th>URL</th><th>Parámetros</th></tr></thead>
  <tbody>{rows}</tbody></table>"""
            if crawl_endpoints:
                rows = "".join(
                    f'<tr><td style="font-family:monospace;font-size:10px">{esc((e.get("url") or "")[:90])}</td>'
                    f'<td>{esc(e.get("method","GET"))}</td></tr>'
                    for e in crawl_endpoints[:100]
                )
                crawl_html += f"""<h3>Todos los endpoints (top 100 de {len(crawl_endpoints)})</h3>
  <table class="dt" style="font-size:11px"><thead><tr><th>URL</th><th style="width:60px">Método</th></tr></thead>
  <tbody>{rows}</tbody></table>"""
            crawl_html += "</div>"
            sections.append(crawl_html)

        # ── OWASP Top 10 Mapping ─────────────────────────────────────
        owasp_map_module = {
            "cors": ["A01"], "takeover": ["A01"], "injection": ["A03","A10","A01"],
            "header_check": ["A05","A02","A07"], "auth_check": ["A07","A05"],
            "tls_ssl": ["A02"], "secrets": ["A02","A07"], "waf": ["A05"],
            "tech_detection": ["A05","A06"], "nuclei": ["A03","A05","A06","A07"],
            "cloud": ["A01","A02","A05"], "fuzzing": ["A01","A05"], "crawl": ["A01"],
        }
        owasp_map_tag = {
            "sql-injection": ["A03"], "xss": ["A03"], "ssrf": ["A10"],
            "path-traversal": ["A01"], "lfi": ["A01"], "jwt": ["A07"],
            "default-credentials": ["A07"], "cookie": ["A02","A07"],
            "hsts": ["A02"], "csp": ["A05","A03"], "headers": ["A05"],
            "misconfiguration": ["A05"], "tls": ["A02"], "ssl": ["A02"],
            "cors": ["A01"], "authentication": ["A07"],
        }
        owasp_cats = [
            ("A01","🔓","Broken Access Control"),
            ("A02","🔐","Cryptographic Failures"),
            ("A03","💉","Injection"),
            ("A04","📐","Insecure Design"),
            ("A05","⚙️","Security Misconfiguration"),
            ("A06","📦","Vulnerable Components"),
            ("A07","🔑","Auth Failures"),
            ("A08","📋","Data Integrity Failures"),
            ("A09","📊","Logging & Monitoring"),
            ("A10","🌐","SSRF"),
        ]
        # Agrupar findings por OWASP
        by_owasp: dict[str, list] = {c[0]: [] for c in owasp_cats}
        for f in findings:
            ids: set[str] = set()
            for oid in owasp_map_module.get(f.get("module", ""), []):
                ids.add(oid)
            for tag in (f.get("tags") or []):
                for oid in owasp_map_tag.get(tag, []):
                    ids.add(oid)
            for oid in ids:
                if oid in by_owasp:
                    by_owasp[oid].append(f)

        # Solo incluir categorías con findings
        has_owasp = any(v for v in by_owasp.values())
        if has_owasp:
            owasp_html = '<div class="section page-break"><h2>OWASP Top 10 — 2021</h2>'
            # Grid de categorías
            grid_cells = "".join(
                f'<td class="sb" style="border-color:{"#dc2626" if by_owasp.get(cid) else "#ddd"}">'
                f'<div class="sn" style="color:{"#dc2626" if by_owasp.get(cid) else "#15803d"}'
                f';font-size:16px">{len(by_owasp.get(cid,[]))}</div>'
                f'<div class="sl">{cid}</div>'
                f'<div style="font-size:9px;color:#888;margin-top:2px">{cicon}</div></td>'
                for cid, cicon, _ctitle in owasp_cats
            )
            owasp_html += f'<table style="width:100%;border-collapse:separate;border-spacing:4px;margin-bottom:14px"><tr>{grid_cells}</tr></table>'
            # Detalle por categoría con findings
            for cid, cicon, ctitle in owasp_cats:
                cat_findings = by_owasp.get(cid, [])
                if not cat_findings:
                    continue
                rows = "".join(
                    f'<tr><td>{badge(f.get("severity","info"))}</td>'
                    f'<td style="font-size:12px">{esc(f.get("title",""))}</td>'
                    f'<td style="font-family:monospace;font-size:11px">{esc(f.get("host",""))}</td>'
                    f'<td style="font-size:11px">{esc(f.get("module",""))}</td></tr>'
                    for f in cat_findings
                )
                owasp_html += (
                    f'<h3>{cicon} {cid} — {ctitle} ({len(cat_findings)} findings)</h3>'
                    f'<table class="dt" style="margin-bottom:10px">'
                    f'<thead><tr><th style="width:70px">Sev</th><th>Título</th>'
                    f'<th style="width:140px">Host</th><th style="width:90px">Módulo</th></tr></thead>'
                    f'<tbody>{rows}</tbody></table>'
                )
            owasp_html += "</div>"
            sections.append(owasp_html)

        # ── CSS + composición final ───────────────────────────────────
        css = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: Arial, Helvetica, sans-serif; font-size: 13px; color: #1a1a1a; line-height: 1.5; }
h2 { font-size: 15px; color: #1e3a5f; margin-bottom: 10px; padding-bottom: 6px;
     border-bottom: 2px solid #1e3a5f; margin-top: 0; }
h3 { font-size: 12px; color: #444; margin: 10px 0 5px; font-weight: 600; }
.section { margin-bottom: 20px; }
.page-break { page-break-before: auto; break-inside: avoid; }
.dt { width: 100%; border-collapse: collapse; font-size: 12px; margin-bottom: 8px; }
.dt th { background: #1e3a5f; color: #fff; padding: 6px 10px; text-align: left;
          font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.3px; }
.dt td { padding: 5px 10px; border-bottom: 1px solid #eee; vertical-align: top; }
.dt tr:nth-child(even) td { background: #f8f9fb; }
.sb { text-align: center; padding: 10px 8px; border: 1px solid #ddd; border-radius: 4px; }
.sn { font-size: 22px; font-weight: 700; }
.sl { font-size: 9px; text-transform: uppercase; color: #888; }
code { font-family: monospace; font-size: 11px; background: #f3f4f6;
       padding: 1px 4px; border-radius: 3px; }
"""
        return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>OrionRecon Report — {esc(target)}</title>
<style>{css}</style>
</head>
<body>
<div style="background:#1e3a5f;color:#fff;padding:16px 20px;margin-bottom:20px;
            display:flex;justify-content:space-between;align-items:center">
  <div>
    <div style="font-size:18px;font-weight:700">⭐ OrionRecon — Security Assessment</div>
    <div style="font-size:11px;color:#93c5fd;margin-top:2px">Attack Surface Recon Toolkit · By Jorge RC</div>
  </div>
  <div style="text-align:right;font-size:11px;color:#93c5fd">
    <div><strong style="color:#fff">{esc(target)}</strong></div>
    <div>{esc(started_at)} → {esc(finished_at)}</div>
  </div>
</div>
{"".join(sections)}
<footer style="margin-top:20px;padding-top:8px;border-top:1px solid #ddd;
               font-size:10px;color:#999;text-align:center">
  OrionRecon · Attack Surface Recon Toolkit · By Jorge RC · {esc(started_at)}
</footer>
</body>
</html>"""
