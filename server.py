#!/usr/bin/env python3
"""
RECON Web Server - Serves the OSINT tool as a local web app.
Usage: python server.py
Then open http://localhost:8420 in your browser.
"""

import asyncio
import json
import sys
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

# Add parent dir to path so we can import the engine
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from recon_engine import full_scan, find_blackbird, find_spiderfoot, find_tool, PLATFORMS, detect_input_type, get_tool_debug_info

PORT = 8420

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RECON - OSINT Aggregator</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700;800;900&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#06060b;--card:#0c0c14;--border:#1a1a2e;--text:#c8c8d4;--dim:#555;--green:#00ff88;--blue:#00aaff;--purple:#8855ff;--red:#ff4466;--orange:#ffaa00;--green-bg:rgba(0,255,136,.06);--blue-bg:rgba(0,170,255,.06)}
body{background:var(--bg);color:var(--text);font-family:'Inter',system-ui,sans-serif;min-height:100vh}
.container{max-width:1100px;margin:0 auto;padding:20px}
.header{text-align:center;padding:40px 0 30px}
.header h1{font-family:'IBM Plex Mono',monospace;font-size:3em;font-weight:900;background:linear-gradient(135deg,var(--green),var(--blue),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:-2px}
.header .sub{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--dim);letter-spacing:4px;margin-top:4px}
.search-box{display:flex;gap:8px;max-width:650px;margin:0 auto 12px}
.search-box input{flex:1;padding:14px 18px;font-size:15px;background:var(--card);border:1px solid var(--border);border-radius:10px;color:var(--text);font-family:'IBM Plex Mono',monospace;outline:none;transition:border .2s}
.search-box input:focus{border-color:var(--green)}
.search-box button{padding:14px 28px;font-size:12px;font-weight:700;font-family:'IBM Plex Mono',monospace;background:var(--green);color:#000;border:none;border-radius:10px;cursor:pointer;letter-spacing:2px;transition:all .2s}
.search-box button:hover{background:#00cc6a}
.search-box button:disabled{background:var(--border);color:var(--dim);cursor:wait}
.options{display:flex;gap:16px;justify-content:center;margin-bottom:30px;flex-wrap:wrap}
.options label{font-size:12px;color:var(--dim);display:flex;align-items:center;gap:5px;cursor:pointer;font-family:'IBM Plex Mono',monospace}
.options input[type=checkbox]{accent-color:var(--green)}
.tool-status{display:flex;gap:10px;justify-content:center;margin-bottom:24px;flex-wrap:wrap}
.tool-pill{font-size:10px;font-family:'IBM Plex Mono',monospace;padding:4px 10px;border-radius:4px;letter-spacing:1px}
.tool-pill.ok{background:var(--green-bg);color:var(--green);border:1px solid rgba(0,255,136,.15)}
.tool-pill.missing{background:rgba(255,68,102,.06);color:var(--red);border:1px solid rgba(255,68,102,.15)}

/* Progress */
.progress-area{max-width:650px;margin:0 auto 24px;display:none}
.progress-area.active{display:block}
.progress-label{font-size:11px;font-family:'IBM Plex Mono',monospace;color:var(--green);letter-spacing:1px;margin-bottom:6px;display:flex;justify-content:space-between}
.progress-bar{height:3px;background:var(--border);border-radius:4px;overflow:hidden}
.progress-fill{height:100%;width:0;background:linear-gradient(90deg,var(--green),var(--blue));border-radius:4px;transition:width .3s}
.log{max-height:200px;overflow-y:auto;font-size:11px;font-family:'IBM Plex Mono',monospace;color:var(--dim);padding:12px;background:var(--card);border:1px solid var(--border);border-radius:8px;margin-top:10px;white-space:pre-wrap}
.log .found{color:var(--green)}
.log .info{color:var(--blue)}
.log .err{color:var(--orange)}

/* Stats */
.stats{display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin-bottom:24px}
.stat{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 22px;text-align:center;min-width:110px}
.stat .n{font-size:28px;font-weight:900;font-family:'IBM Plex Mono',monospace}
.stat .l{font-size:9px;color:var(--dim);letter-spacing:1px;margin-top:3px;font-family:'IBM Plex Mono',monospace}

/* Tabs */
.tabs{display:flex;gap:2px;background:var(--card);border-radius:10px;padding:3px;margin-bottom:20px;justify-content:center}
.tab{padding:10px 20px;font-size:11px;font-weight:600;font-family:'IBM Plex Mono',monospace;background:transparent;color:var(--dim);border:1px solid transparent;border-radius:8px;cursor:pointer;letter-spacing:1px;transition:all .2s}
.tab.active{background:var(--green-bg);color:var(--green);border-color:rgba(0,255,136,.2)}

/* Results */
.results-panel{display:none}.results-panel.active{display:block}
.section-title{font-size:11px;font-family:'IBM Plex Mono',monospace;letter-spacing:3px;font-weight:700;margin:20px 0 10px;display:flex;align-items:center;gap:8px}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:6px;transition:border .2s}
.card:hover{border-color:rgba(255,255,255,.1)}
.card.found-card{border-left:3px solid var(--green)}
.card-row{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px}
.card-title{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.badge{font-size:9px;padding:2px 7px;border-radius:3px}
.badge.cat{background:var(--blue-bg);color:var(--blue)}
.badge.src{font-size:8px;background:var(--green-bg);color:#0a6}
.conf{font-size:22px;font-weight:900;font-family:'IBM Plex Mono',monospace;color:var(--green)}
.profile-link{color:var(--blue);font-size:12px;font-family:'IBM Plex Mono',monospace;text-decoration:none;word-break:break-all;display:block;margin:6px 0 2px}
.profile-link:hover{text-decoration:underline}
.info-chips{margin-top:8px;display:flex;flex-wrap:wrap;gap:4px}
.chip{font-size:10px;font-family:'IBM Plex Mono',monospace;background:var(--green-bg);border:1px solid rgba(0,255,136,.1);color:#8f8;padding:2px 8px;border-radius:3px}
.nf-chip{display:inline-block;font-size:10px;font-family:'IBM Plex Mono',monospace;padding:3px 8px;border-radius:3px;margin:2px;background:rgba(255,255,255,.03);color:var(--dim)}
.err-chip{display:inline-block;font-size:10px;font-family:'IBM Plex Mono',monospace;padding:3px 8px;border-radius:3px;margin:2px;background:rgba(255,170,0,.08);color:var(--orange);cursor:help}
.var-chip{display:inline-block;font-size:12px;font-family:'IBM Plex Mono',monospace;padding:7px 14px;background:rgba(136,85,255,.08);border:1px solid rgba(136,85,255,.15);color:#a88fff;border-radius:6px;margin:3px;text-decoration:none;cursor:pointer;transition:background .2s}
.var-chip:hover{background:rgba(136,85,255,.18)}
.tool-link{display:inline-block;font-size:11px;font-family:'IBM Plex Mono',monospace;padding:10px 16px;background:var(--blue-bg);border:1px solid rgba(0,170,255,.1);border-radius:6px;margin:3px;text-decoration:none;color:#88ccff;transition:background .2s}
.tool-link:hover{background:rgba(0,170,255,.12)}
.tool-link strong{color:var(--text);display:block;margin-bottom:2px}
.footer{text-align:center;margin-top:40px;padding:20px 0;border-top:1px solid var(--border);font-size:9px;font-family:'IBM Plex Mono',monospace;color:#333;letter-spacing:1px}
.hidden{display:none}
.filter-bar{display:flex;gap:6px;margin-bottom:16px;flex-wrap:wrap;justify-content:center}
.filter-btn{padding:5px 12px;font-size:10px;font-family:'IBM Plex Mono',monospace;background:rgba(255,255,255,.03);color:var(--dim);border:1px solid var(--border);border-radius:5px;cursor:pointer;letter-spacing:1px;transition:all .2s}
.filter-btn.active{background:var(--blue-bg);color:var(--blue);border-color:rgba(0,170,255,.3)}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>RECON</h1>
    <div class="sub">MULTI-SOURCE OSINT AGGREGATOR</div>
  </div>

  <div class="search-box">
    <input type="text" id="query" placeholder="Enter username or email..." autofocus>
    <button id="searchBtn" onclick="startScan()">SCAN</button>
  </div>

  <div class="options">
    <label><input type="checkbox" id="optWMN" checked> WhatsMyName (500+ sites)</label>
    <label><input type="checkbox" id="optExt" checked> External tools (Blackbird/Maigret/Sherlock)</label>
  </div>

  <div class="tool-status" id="toolStatus"></div>

  <div class="progress-area" id="progressArea">
    <div class="progress-label"><span id="progressText">Initializing...</span><span id="progressPct">0%</span></div>
    <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
    <div class="log" id="logArea"></div>
  </div>

  <div id="resultsArea" class="hidden">
    <div class="stats" id="statsBar"></div>
    <div class="tabs" id="tabsBar"></div>

    <div class="results-panel active" id="panelFound">
      <div class="filter-bar" id="filterBar"></div>
      <div id="foundList"></div>
    </div>
    <div class="results-panel" id="panelNotFound"></div>
    <div class="results-panel" id="panelVariants"></div>
    <div class="results-panel" id="panelTools"></div>
    <div class="results-panel" id="panelExport"></div>
  </div>

  <div class="footer">RECON OSINT Aggregator &bull; All results from real HTTP checks &bull; Verify independently</div>
</div>

<script>
let currentData = null;
let activeTab = 'found';
let activeFilter = 'All';

document.getElementById('query').addEventListener('keydown', e => { if(e.key==='Enter') startScan(); });

// Check tool status on load
fetch('/api/status').then(r=>r.json()).then(d=>{
  const el = document.getElementById('toolStatus');
  const tools = [
    {name:'Built-in', ok:true, count: d.builtin_count},
    {name:'WhatsMyName', ok:true, count:'500+'},
    {name:'Blackbird', ok:d.blackbird},
    {name:'SpiderFoot', ok:d.spiderfoot},
    {name:'Maigret', ok:d.maigret},
    {name:'Sherlock', ok:d.sherlock},
    {name:'Holehe', ok:d.holehe},
  ];
  let html = tools.map(t =>
    `<span class="tool-pill ${t.ok?'ok':'missing'}">${t.ok?'OK':'MISSING'} ${t.name}${t.count?' ('+t.count+')':''}</span>`
  ).join('');

  // Show debug info if any tool missing
  const missing = tools.filter(t => !t.ok && !['Built-in','WhatsMyName'].includes(t.name));
  if(missing.length && d.debug){
    html += `<div style="margin-top:10px;font-size:10px;font-family:'IBM Plex Mono',monospace;color:var(--dim);text-align:left;max-width:700px;margin-left:auto;margin-right:auto;background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px">
      <div style="color:var(--orange);margin-bottom:6px">Tool Detection Debug:</div>
      <div>Script dir: ${d.debug.script_dir}</div>
      <div>CWD: ${d.debug.cwd}</div>
      <div style="margin-top:4px">Blackbird path: ${d.debug.blackbird || 'NOT FOUND'}</div>
      ${d.debug.blackbird_searched ? d.debug.blackbird_searched.map(s=>'<div style="color:#444">  '+s+'</div>').join('') : ''}
      <div style="margin-top:4px">SpiderFoot path: ${d.debug.spiderfoot || 'NOT FOUND'}</div>
      ${d.debug.spiderfoot_searched ? d.debug.spiderfoot_searched.map(s=>'<div style="color:#444">  '+s+'</div>').join('') : ''}
      <div style="margin-top:8px;color:var(--blue)">Fix: clone tools into the same folder as server.py, then restart.</div>
    </div>`;
  }
  el.innerHTML = html;
});

function startScan(){
  const q = document.getElementById('query').value.trim();
  if(!q) return;
  const wmn = document.getElementById('optWMN').checked;
  const ext = document.getElementById('optExt').checked;
  const btn = document.getElementById('searchBtn');
  btn.disabled = true; btn.textContent = 'SCANNING...';

  document.getElementById('progressArea').classList.add('active');
  document.getElementById('resultsArea').classList.add('hidden');
  document.getElementById('logArea').textContent = '';
  setProgress(0, 'Starting scan...');

  fetch(`/api/scan?q=${encodeURIComponent(q)}&wmn=${wmn}&ext=${ext}`)
    .then(r=>r.json())
    .then(data=>{
      currentData = data;
      btn.disabled = false; btn.textContent = 'SCAN';
      document.getElementById('progressArea').classList.remove('active');
      renderResults(data);
    })
    .catch(err=>{
      btn.disabled = false; btn.textContent = 'SCAN';
      log('Error: ' + err.message, 'err');
    });

  // Poll progress
  const poll = setInterval(()=>{
    fetch('/api/progress').then(r=>r.json()).then(p=>{
      setProgress(p.pct, p.msg);
      if(p.logs) p.logs.forEach(l => log(l.text, l.type));
      if(p.done) clearInterval(poll);
    }).catch(()=>{});
  }, 500);
}

function setProgress(pct, msg){
  document.getElementById('progressFill').style.width = pct+'%';
  document.getElementById('progressText').textContent = msg;
  document.getElementById('progressPct').textContent = pct+'%';
}

function log(text, type='info'){
  const el = document.getElementById('logArea');
  const span = document.createElement('span');
  span.className = type||'info';
  span.textContent = text + '\n';
  el.appendChild(span);
  el.scrollTop = el.scrollHeight;
}

function renderResults(data){
  document.getElementById('resultsArea').classList.remove('hidden');

  // Stats
  document.getElementById('statsBar').innerHTML = [
    {n:data.summary.checked, l:'CHECKED', c:'var(--blue)'},
    {n:data.summary.found, l:'FOUND', c:'var(--green)'},
    {n:data.summary.not_found, l:'NOT FOUND', c:'var(--red)'},
    {n:data.summary.errors, l:'ERRORS', c:'var(--orange)'},
    {n:data.variants.length, l:'VARIANTS', c:'var(--purple)'},
  ].map(s=>`<div class="stat"><div class="n" style="color:${s.c}">${s.n}</div><div class="l">${s.l}</div></div>`).join('');

  // Tabs
  const tabs = [
    {id:'found',label:`Found (${data.summary.found})`},
    {id:'notfound',label:`Not Found`},
    {id:'variants',label:`Variants (${data.variants.length})`},
    {id:'tools',label:`OSINT Tools (${data.cross_reference.length})`},
    {id:'export',label:'Export'},
  ];
  document.getElementById('tabsBar').innerHTML = tabs.map(t=>
    `<div class="tab ${t.id===activeTab?'active':''}" onclick="switchTab('${t.id}')">${t.label}</div>`
  ).join('');

  renderFound(data);
  renderNotFound(data);
  renderVariants(data);
  renderTools(data);
  renderExport(data);
  switchTab(activeTab);
}

function switchTab(id){
  activeTab = id;
  document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('active', t.textContent.toLowerCase().startsWith(id.replace('notfound','not'))));
  document.querySelectorAll('.results-panel').forEach(p=>p.classList.remove('active'));
  const map = {found:'panelFound',notfound:'panelNotFound',variants:'panelVariants',tools:'panelTools',export:'panelExport'};
  document.getElementById(map[id]).classList.add('active');
  // Re-highlight tab
  document.querySelectorAll('.tab').forEach((t,i)=>{
    t.classList.toggle('active', tabs_order[i]===id);
  });
}
const tabs_order = ['found','notfound','variants','tools','export'];

function renderFound(data){
  const found = data.found;
  // Get categories
  const cats = ['All', ...new Set(found.map(f=>f.category))];
  document.getElementById('filterBar').innerHTML = cats.map(c=>
    `<div class="filter-btn ${c===activeFilter?'active':''}" onclick="filterCat('${c}')">${c}</div>`
  ).join('');

  const filtered = activeFilter==='All' ? found : found.filter(f=>f.category===activeFilter);
  const high = filtered.filter(f=>f.confidence>=70);
  const med = filtered.filter(f=>f.confidence>=40 && f.confidence<70);
  const low = filtered.filter(f=>f.confidence<40);

  let html = '';
  if(high.length){
    html += `<div class="section-title" style="color:var(--green)"><span class="dot" style="background:var(--green);box-shadow:0 0 6px rgba(0,255,136,.4)"></span>HIGH PROBABILITY (${high.length})</div>`;
    html += high.map(cardHtml).join('');
  }
  if(med.length){
    html += `<div class="section-title" style="color:var(--orange)"><span class="dot" style="background:var(--orange)"></span>MEDIUM PROBABILITY (${med.length})</div>`;
    html += med.map(cardHtml).join('');
  }
  if(low.length){
    html += `<div class="section-title" style="color:var(--dim)"><span class="dot" style="background:#444"></span>LOW PROBABILITY (${low.length})</div>`;
    html += low.map(cardHtml).join('');
  }
  if(!found.length) html = '<div class="card">No accounts found.</div>';
  document.getElementById('foundList').innerHTML = html;
}

function filterCat(c){ activeFilter=c; renderFound(currentData); }

function cardHtml(r){
  const srcs = r.source.split('+').map(s=>`<span class="badge src">${esc(s)}</span>`).join('');
  let info = '';
  if(r.info && Object.keys(r.info).length){
    const chips = Object.entries(r.info)
      .filter(([k])=>!['avatar','icon_img','profile_image','avatar_url','banner_image','banner'].some(s=>k.toLowerCase().includes(s)))
      .map(([k,v])=>`<span class="chip">${esc(k)}: ${esc(String(v).substring(0,120))}</span>`)
      .join('');
    if(chips) info = `<div class="info-chips">${chips}</div>`;
  }
  return `<div class="card found-card">
    <div class="card-row">
      <div class="card-title"><strong>${esc(r.platform)}</strong><span class="badge cat">${esc(r.category)}</span>${srcs}</div>
      <div class="conf">${r.confidence.toFixed(0)}%</div>
    </div>
    <a href="${esc(r.profile_url)}" target="_blank" class="profile-link">${esc(r.profile_url)}</a>
    ${info}
  </div>`;
}

function renderNotFound(data){
  const html = data.not_found.map(n=>`<span class="nf-chip">${esc(n)}</span>`).join(' ');
  const errHtml = data.errors.map(e=>`<span class="err-chip" title="${esc(e.error||'')}">${esc(e.platform)}</span>`).join(' ');
  document.getElementById('panelNotFound').innerHTML =
    `<div class="section-title" style="color:var(--red)">NOT FOUND (${data.not_found.length})</div><div class="card">${html||'None'}</div>` +
    (data.errors.length ? `<div class="section-title" style="color:var(--orange)">ERRORS (${data.errors.length})</div><div class="card">${errHtml}</div>` : '');
}

function renderVariants(data){
  const html = data.variants.map(v=>
    `<span class="var-chip" onclick="document.getElementById('query').value='${esc(v)}';startScan()">@${esc(v)}</span>`
  ).join(' ');
  document.getElementById('panelVariants').innerHTML =
    `<div class="section-title" style="color:var(--purple)">USERNAME VARIANTS (${data.variants.length})</div>
    <div class="card">${html}</div>
    <div class="card" style="margin-top:12px;font-size:11px;color:var(--dim);line-height:1.8">
      Variants are generated from real patterns: separator swaps, number suffix removal,
      common prefixes (real/the/official/its), suffix removal (xo/xx/irl).
      Click a variant to scan it.
    </div>`;
}

function renderTools(data){
  const byCat = {};
  data.cross_reference.forEach(t=>{ if(!byCat[t.cat]) byCat[t.cat]=[]; byCat[t.cat].push(t); });
  let html = '';
  for(const [cat, tools] of Object.entries(byCat)){
    html += `<div class="section-title" style="color:var(--blue)">${cat.toUpperCase()}</div><div class="card">`;
    html += tools.map(t=>`<a href="${esc(t.url)}" target="_blank" class="tool-link"><strong>${esc(t.tool)}</strong>${esc(t.url.substring(0,60))}</a>`).join(' ');
    html += '</div>';
  }
  document.getElementById('panelTools').innerHTML = html;
}

function renderExport(data){
  document.getElementById('panelExport').innerHTML = `
    <div class="section-title" style="color:var(--blue)">EXPORT RESULTS</div>
    <div class="card" style="display:flex;gap:10px;flex-wrap:wrap">
      <button onclick="downloadJSON()" style="padding:10px 20px;font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:700;background:var(--green-bg);color:var(--green);border:1px solid rgba(0,255,136,.2);border-radius:6px;cursor:pointer;letter-spacing:1px">DOWNLOAD JSON</button>
      <button onclick="downloadCSV()" style="padding:10px 20px;font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:700;background:var(--blue-bg);color:var(--blue);border:1px solid rgba(0,170,255,.2);border-radius:6px;cursor:pointer;letter-spacing:1px">DOWNLOAD CSV</button>
      <button onclick="downloadTXT()" style="padding:10px 20px;font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:700;background:rgba(136,85,255,.08);color:var(--purple);border:1px solid rgba(136,85,255,.2);border-radius:6px;cursor:pointer;letter-spacing:1px">DOWNLOAD TXT</button>
    </div>
    <div class="section-title" style="color:var(--dim);margin-top:16px">RAW JSON</div>
    <pre class="card" style="font-size:10px;font-family:'IBM Plex Mono',monospace;color:var(--dim);max-height:400px;overflow:auto;white-space:pre-wrap">${esc(JSON.stringify(data,null,2))}</pre>
    <div class="section-title" style="color:var(--dim);margin-top:12px">SOURCES USED</div>
    <div class="card" style="font-size:12px">${data.sources.join(' + ')}</div>`;
}

function downloadJSON(){
  const blob = new Blob([JSON.stringify(currentData,null,2)],{type:'application/json'});
  dl(blob, `recon_${currentData.target}.json`);
}
function downloadCSV(){
  let csv = 'Platform,Category,URL,Confidence,Source\n';
  currentData.found.forEach(r=>csv+=`"${r.platform}","${r.category}","${r.profile_url}",${r.confidence},"${r.source}"\n`);
  dl(new Blob([csv],{type:'text/csv'}), `recon_${currentData.target}.csv`);
}
function downloadTXT(){
  let txt = `RECON Report: ${currentData.target}\nDate: ${currentData.timestamp}\nSources: ${currentData.sources.join(', ')}\n\n`;
  txt += `=== FOUND (${currentData.found.length}) ===\n`;
  currentData.found.forEach(r=>txt+=`[${r.confidence.toFixed(0)}%] ${r.platform} (${r.source}) -> ${r.profile_url}\n`);
  txt += `\n=== VARIANTS ===\n`;
  currentData.variants.forEach(v=>txt+=`  @${v}\n`);
  dl(new Blob([txt],{type:'text/plain'}), `recon_${currentData.target}.txt`);
}
function dl(blob, name){ const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=name; a.click(); }
function esc(s){ const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }
</script>
</body>
</html>"""


# =================================================================
# Progress tracking
# =================================================================

progress_state = {"pct": 0, "msg": "Idle", "logs": [], "done": False, "log_cursor": 0}

def reset_progress():
    progress_state["pct"] = 0
    progress_state["msg"] = "Idle"
    progress_state["logs"] = []
    progress_state["done"] = False
    progress_state["log_cursor"] = 0

def add_log(text, ltype="info"):
    progress_state["logs"].append({"text": text, "type": ltype})

def progress_callback(event, current, total, detail):
    if event == "phase":
        progress_state["msg"] = f"Phase {current}/{total}: {detail}"
        add_log(f"--- Phase {current}: {detail} ---", "info")
    elif event == "builtin":
        pct = int((current / total) * 40)  # 0-40% for phase 1
        progress_state["pct"] = pct
        progress_state["msg"] = f"Built-in: {current}/{total}"
        if detail and detail.exists:
            info_str = ""
            if detail.info:
                preview = [(k,v) for k,v in list(detail.info.items())[:2]
                           if not any(s in k.lower() for s in ["avatar","icon","image"])]
                if preview: info_str = " | " + " | ".join(f"{k}={v}" for k,v in preview)
            add_log(f"[+] {detail.platform} -> {detail.profile_url}{info_str}", "found")
    elif event == "wmn_start":
        progress_state["msg"] = f"WhatsMyName: scanning {total} sites..."
        progress_state["pct"] = 40
    elif event == "wmn_progress":
        pct = 40 + int((current / max(total,1)) * 40)  # 40-80%
        progress_state["pct"] = pct
        progress_state["msg"] = f"WhatsMyName: {current}/{total}"
    elif event == "tool_start":
        progress_state["pct"] = min(progress_state["pct"] + 2, 95)
        progress_state["msg"] = f"Running {detail}..."
        add_log(f"[*] Running {detail}...", "info")
    elif event == "tool_done":
        progress_state["pct"] = min(progress_state["pct"] + 5, 98)
        add_log(f"[+] {detail}: {current} accounts found", "found" if current > 0 else "info")
    elif event == "tool_error":
        add_log(f"[!] {detail}", "err")
    elif event == "ext_found":
        if detail and hasattr(detail, 'platform'):
            add_log(f"    [+] {detail.platform} -> {detail.profile_url}", "found")


# =================================================================
# HTTP Handler
# =================================================================

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass  # Silence logs

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))

        elif path == "/api/status":
            debug = get_tool_debug_info()
            status = {
                "builtin_count": len(PLATFORMS),
                "blackbird": find_blackbird() is not None,
                "spiderfoot": find_spiderfoot() is not None,
                "maigret": find_tool("maigret"),
                "sherlock": find_tool("sherlock"),
                "holehe": find_tool("holehe"),
                "debug": debug,
            }
            self._json(status)

        elif path == "/api/scan":
            q = params.get("q", [""])[0]
            wmn = params.get("wmn", ["true"])[0] == "true"
            ext = params.get("ext", ["true"])[0] == "true"

            if not q:
                self._json({"error": "No query"}, 400)
                return

            reset_progress()
            progress_state["msg"] = "Starting scan..."

            loop = asyncio.new_event_loop()
            try:
                report = loop.run_until_complete(
                    full_scan(q, skip_wmn=not wmn, skip_external=not ext,
                              callback=progress_callback))
            finally:
                loop.close()

            progress_state["done"] = True
            progress_state["pct"] = 100
            progress_state["msg"] = "Complete"
            self._json(report)

        elif path == "/api/progress":
            cursor = progress_state.get("log_cursor", 0)
            new_logs = progress_state["logs"][cursor:]
            progress_state["log_cursor"] = len(progress_state["logs"])
            self._json({
                "pct": progress_state["pct"],
                "msg": progress_state["msg"],
                "done": progress_state["done"],
                "logs": new_logs,
            })

        else:
            self.send_response(404)
            self.end_headers()

    def _json(self, data, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str, ensure_ascii=False).encode("utf-8"))


def main():
    debug = get_tool_debug_info()
    print(f"\n  RECON Web Server")
    print(f"  ================")
    print(f"  Open in browser: http://localhost:{PORT}")
    print(f"  Built-in platforms: {len(PLATFORMS)}")
    print(f"")
    print(f"  Script dir:  {debug['script_dir']}")
    print(f"  Working dir: {debug['cwd']}")
    print(f"")
    bb = find_blackbird()
    sf = find_spiderfoot()
    print(f"  Blackbird:   {bb or 'NOT FOUND'}")
    if not bb:
        for s in debug.get('blackbird_searched', []):
            print(f"    checked: {s}")
    print(f"  SpiderFoot:  {sf or 'NOT FOUND'}")
    if not sf:
        for s in debug.get('spiderfoot_searched', []):
            print(f"    checked: {s}")
    print(f"  Maigret:     {'FOUND' if find_tool('maigret') else 'NOT FOUND (pip install maigret)'}")
    print(f"  Sherlock:    {'FOUND' if find_tool('sherlock') else 'NOT FOUND (pip install sherlock-project)'}")
    print(f"  Holehe:      {'FOUND' if find_tool('holehe') else 'NOT FOUND (pip install holehe)'}")
    print(f"")
    if not bb or not sf:
        print(f"  TIP: Clone tools into this folder:")
        print(f"    cd {debug['script_dir']}")
        if not bb: print(f"    git clone https://github.com/p1ngul1n0/blackbird.git")
        if not sf: print(f"    git clone https://github.com/smicallef/spiderfoot.git")
        print(f"    Then restart server.py")
        print(f"")
    print(f"  Press Ctrl+C to stop.\n")

    server = HTTPServer(("0.0.0.0", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")
        server.server_close()


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    main()
