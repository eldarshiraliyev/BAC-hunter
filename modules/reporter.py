"""
Reporter Module v3.0 — Yeni tapıntı tipləri, score göstərilməsi, improved HTML
"""

import json
import os
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich import box

from config import SEVERITY_ORDER

console = Console()

# ── Severity mapping ──────────────────────────────────────────────────────────
_SEV_COLOR = {
    "CRITICAL": "#FF3B30",
    "HIGH":     "#FF9500",
    "MEDIUM":   "#FFCC00",
    "LOW":      "#30D158",
    "INFO":     "#0A84FF",
}
_SEV_RICH = {
    "CRITICAL": "red", "HIGH": "yellow",
    "MEDIUM": "bright_yellow", "LOW": "green", "INFO": "cyan",
}

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BAC Hunter Report</title>
<style>
:root {
  --bg:#0d1117;--surface:#161b22;--surface2:#21262d;--border:#30363d;
  --text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;
  --critical:#FF3B30;--high:#FF9500;--medium:#FFCC00;--low:#30D158;--info:#0A84FF;
  --radius:10px;--mono:'SF Mono','Fira Code','Cascadia Code',monospace;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:var(--mono);background:var(--bg);color:var(--text);min-height:100vh;}
header{background:var(--surface);border-bottom:1px solid var(--border);padding:18px 36px;
  display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;}
.logo{font-size:20px;font-weight:800;letter-spacing:-1px;}
.logo span{color:var(--critical);}
.header-meta{font-size:11px;color:var(--muted);margin-top:3px;}
.export-btn{background:var(--surface2);border:1px solid var(--border);color:var(--text);
  padding:7px 16px;border-radius:var(--radius);font-family:var(--mono);
  font-size:11px;cursor:pointer;transition:border-color .2s;}
.export-btn:hover{border-color:var(--accent);color:var(--accent);}
main{max-width:1200px;margin:0 auto;padding:28px 20px 60px;}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:32px;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:16px;text-align:center;transition:border-color .2s;}
.stat-card:hover{border-color:var(--accent);}
.stat-num{font-size:30px;font-weight:800;line-height:1;}
.stat-lbl{font-size:9px;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:1.2px;}
.c-critical{color:var(--critical)}.c-high{color:var(--high)}.c-medium{color:var(--medium)}
.c-low{color:var(--low)}.c-muted{color:var(--muted)}
.toolbar{display:flex;align-items:center;gap:8px;margin-bottom:18px;flex-wrap:wrap;}
.filter-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted);
  padding:5px 12px;border-radius:20px;font-family:var(--mono);font-size:11px;cursor:pointer;
  transition:all .15s;font-weight:600;}
.filter-btn:hover,.filter-btn.active{border-color:var(--accent);color:var(--accent);background:#58a6ff14;}
.filter-btn.sev-CRITICAL.active{border-color:var(--critical);color:var(--critical);background:#FF3B3014;}
.filter-btn.sev-HIGH.active{border-color:var(--high);color:var(--high);background:#FF950014;}
.filter-btn.sev-MEDIUM.active{border-color:var(--medium);color:var(--medium);background:#FFCC0014;}
.filter-btn.sev-LOW.active{border-color:var(--low);color:var(--low);background:#30D15814;}
.search-box{flex:1;min-width:180px;background:var(--surface);border:1px solid var(--border);
  color:var(--text);padding:5px 12px;border-radius:20px;font-family:var(--mono);
  font-size:12px;outline:none;}
.search-box:focus{border-color:var(--accent);}
.section-head{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:2px;
  margin-bottom:12px;border-bottom:1px solid var(--border);padding-bottom:7px;
  display:flex;align-items:center;justify-content:space-between;}
.finding{background:var(--surface);border:1px solid var(--border);
  border-left:4px solid var(--critical);border-radius:0 var(--radius) var(--radius) 0;
  padding:16px 18px;margin-bottom:10px;transition:box-shadow .15s;}
.finding:hover{box-shadow:0 4px 20px #00000050;}
.finding[data-sev="HIGH"]{border-left-color:var(--high);}
.finding[data-sev="MEDIUM"]{border-left-color:var(--medium);}
.finding[data-sev="LOW"]{border-left-color:var(--low);}
.finding-head{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px;}
.badge{font-size:9px;font-weight:800;padding:2px 8px;border-radius:20px;
  text-transform:uppercase;letter-spacing:1px;}
.badge-CRITICAL{background:#FF3B3020;color:var(--critical);border:1px solid #FF3B3040;}
.badge-HIGH{background:#FF950020;color:var(--high);border:1px solid #FF950040;}
.badge-MEDIUM{background:#FFCC0020;color:var(--medium);border:1px solid #FFCC0040;}
.badge-LOW{background:#30D15820;color:var(--low);border:1px solid #30D15840;}
.finding-type{font-size:13px;font-weight:700;}
.pill{font-size:9px;padding:2px 7px;border-radius:5px;background:var(--surface2);
  color:var(--muted);font-weight:600;}
.pill-method{background:#58a6ff14;color:var(--accent);}
.pill-status-ok{background:#30D15814;color:var(--low);}
.pill-status-err{background:#FF3B3014;color:var(--critical);}
.finding-url{font-size:11px;color:var(--accent);word-break:break-all;
  margin-bottom:6px;display:flex;align-items:flex-start;gap:6px;}
.finding-url a{color:inherit;text-decoration:none;}
.finding-url a:hover{text-decoration:underline;}
.copy-btn{flex-shrink:0;background:none;border:none;color:var(--muted);cursor:pointer;
  font-size:12px;padding:0 3px;transition:color .15s;}
.copy-btn:hover{color:var(--accent);}
.finding-reason{font-size:11px;color:var(--muted);margin-bottom:8px;}
.signals{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:6px;}
.signal-tag{font-size:9px;padding:2px 6px;border-radius:4px;
  background:#30D15820;color:var(--low);border:1px solid #30D15840;font-weight:600;}
.details-toggle{font-size:10px;color:var(--muted);cursor:pointer;background:none;
  border:none;font-family:var(--mono);padding:0;transition:color .15s;}
.details-toggle:hover{color:var(--accent);}
.code-block{background:var(--bg);border:1px solid var(--border);border-radius:6px;
  padding:10px;margin-top:8px;font-size:10px;color:var(--muted);overflow-x:auto;
  white-space:pre-wrap;word-break:break-all;max-height:160px;overflow-y:auto;display:none;}
.chart-wrap{margin-bottom:32px;}
.chart-bar-row{display:flex;align-items:center;gap:10px;margin-bottom:6px;font-size:11px;}
.chart-bar-label{width:180px;color:var(--muted);flex-shrink:0;font-size:10px;}
.chart-bar-track{flex:1;background:var(--surface2);border-radius:4px;height:14px;overflow:hidden;}
.chart-bar-fill{height:100%;border-radius:4px;transition:width .6s cubic-bezier(.22,1,.36,1);}
.chart-bar-count{width:28px;text-align:right;color:var(--text);font-weight:700;font-size:11px;}
.empty{text-align:center;padding:70px 0;color:var(--muted);}
.empty-icon{font-size:40px;margin-bottom:10px;}
footer{text-align:center;padding:28px;color:var(--muted);font-size:10px;
  border-top:1px solid var(--border);margin-top:50px;}
</style>
</head>
<body>
<header>
  <div>
    <div class="logo">BAC<span>Hunter</span> <span style="font-size:12px;font-weight:400;color:var(--muted)">v3.0</span></div>
    <div class="header-meta">OWASP Top 10 #1 · 250 real bug bounty report əsasında · {{date}}</div>
  </div>
  <button class="export-btn" onclick="exportJSON()">⬇ Export JSON</button>
</header>
<main>
  <div class="stats">
    <div class="stat-card"><div class="stat-num c-muted">{{total}}</div><div class="stat-lbl">Total</div></div>
    <div class="stat-card"><div class="stat-num c-critical">{{critical}}</div><div class="stat-lbl">Critical</div></div>
    <div class="stat-card"><div class="stat-num c-high">{{high}}</div><div class="stat-lbl">High</div></div>
    <div class="stat-card"><div class="stat-num c-medium">{{medium}}</div><div class="stat-lbl">Medium</div></div>
    <div class="stat-card"><div class="stat-num c-low">{{low}}</div><div class="stat-lbl">Low</div></div>
    <div class="stat-card"><div class="stat-num c-muted" style="font-size:14px;padding-top:6px">{{scan_time}}</div><div class="stat-lbl">Scan Time</div></div>
    <div class="stat-card"><div class="stat-num c-muted" style="font-size:14px;padding-top:6px">{{req_count}}</div><div class="stat-lbl">Requests</div></div>
  </div>
  <div class="chart-wrap" id="chartWrap"></div>
  <div class="toolbar">
    <button class="filter-btn active" data-filter="ALL" onclick="setFilter('ALL',this)">All</button>
    <button class="filter-btn sev-CRITICAL" data-filter="CRITICAL" onclick="setFilter('CRITICAL',this)">🔴 Critical</button>
    <button class="filter-btn sev-HIGH"     data-filter="HIGH"     onclick="setFilter('HIGH',this)">🟠 High</button>
    <button class="filter-btn sev-MEDIUM"   data-filter="MEDIUM"   onclick="setFilter('MEDIUM',this)">🟡 Medium</button>
    <button class="filter-btn sev-LOW"      data-filter="LOW"      onclick="setFilter('LOW',this)">🟢 Low</button>
    <input class="search-box" id="searchBox" placeholder="🔍  filter by URL, type, technique…" oninput="applyFilters()">
  </div>
  <div class="section-head">
    <span>Findings</span>
    <span id="countLabel" style="color:var(--accent)"></span>
  </div>
  <div id="findings">{{findings_html}}</div>
</main>
<footer>Generated by BAC Hunter v3.0 · {{date}} · Yalnız icazəli testlər üçün</footer>
<script>
const RAW={{findings_json}};
let currentFilter='ALL';
function setFilter(sev,btn){
  currentFilter=sev;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');applyFilters();
}
function applyFilters(){
  const q=document.getElementById('searchBox').value.toLowerCase();
  let visible=0;
  document.querySelectorAll('.finding').forEach(el=>{
    const sev=el.dataset.sev,text=el.dataset.search||'';
    const show=(currentFilter==='ALL'||sev===currentFilter)&&(!q||text.includes(q));
    el.style.display=show?'':'none';
    if(show)visible++;
  });
  document.getElementById('countLabel').textContent=`${visible} shown`;
}
function toggleSnippet(id){
  const el=document.getElementById('snippet-'+id);
  const btn=document.getElementById('btn-'+id);
  if(!el.style.display||el.style.display==='none'){el.style.display='block';btn.textContent='▲ hide';}
  else{el.style.display='none';btn.textContent='▼ show response';}
}
function copyURL(url){navigator.clipboard.writeText(url).catch(()=>{});}
function exportJSON(){
  const blob=new Blob([JSON.stringify(RAW,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='bac_report.json';a.click();
}
function buildChart(){
  const counts={};RAW.forEach(r=>{counts[r.type]=(counts[r.type]||0)+1;});
  const sorted=Object.entries(counts).sort((a,b)=>b[1]-a[1]);
  const max=sorted[0]?.[1]||1;
  const wrap=document.getElementById('chartWrap');
  if(!sorted.length){wrap.style.display='none';return;}
  const colors={'IDOR':'#FF3B30','IDOR (Write Operation)':'#FF3B30',
    'RBAC Bypass':'#FF9500','JWT Attack':'#FFCC00','JWT Weak Secret':'#FFCC00',
    'Forced Browsing':'#30D158','HTTP Method Tampering':'#0A84FF',
    'GraphQL IDOR':'#BF5AF2'};
  wrap.innerHTML='<div class="section-head"><span>Finding Distribution</span></div>'+
    sorted.map(([type,count])=>`
      <div class="chart-bar-row">
        <div class="chart-bar-label">${type}</div>
        <div class="chart-bar-track">
          <div class="chart-bar-fill" style="width:0%;background:${colors[type]||'#58a6ff'}"
               data-pct="${(count/max*100).toFixed(1)}"></div>
        </div>
        <div class="chart-bar-count">${count}</div>
      </div>`).join('');
  requestAnimationFrame(()=>{
    document.querySelectorAll('.chart-bar-fill').forEach(el=>{el.style.width=el.dataset.pct+'%';});
  });
}
buildChart();applyFilters();
</script>
</body>
</html>"""


def _method_pill(r: dict) -> str:
    m = r.get("method") or r.get("technique") or r.get("attack") or ""
    return f'<span class="pill pill-method">{m}</span>' if m else ""

def _status_pill(status) -> str:
    if status is None:
        return ""
    css = "pill-status-ok" if int(status) < 300 else "pill-status-err"
    return f'<span class="pill {css}">HTTP {status}</span>'

def _signals_html(r: dict) -> str:
    signals = r.get("signals") or []
    if not signals:
        return ""
    tags = "".join(f'<span class="signal-tag">🔑 {s}</span>' for s in signals[:5])
    return f'<div class="signals">{tags}</div>'

def _render_finding(f: dict, idx: int) -> str:
    sev     = f.get("severity", "INFO")
    ftype   = f.get("type", "Finding")
    url     = f.get("url", "")
    reason  = f.get("reason", "")
    snippet = (f.get("snippet") or "").strip()
    search  = f"{ftype} {url} {reason} {sev} {f.get('method','')} {f.get('attack','')}".lower()

    toggle = snippet and f'<button class="details-toggle" id="btn-{idx}" onclick="toggleSnippet({idx})">▼ show response</button>' or ""
    code   = snippet and f'<div class="code-block" id="snippet-{idx}">{snippet}</div>' or ""

    return f"""
<div class="finding" data-sev="{sev}" data-search="{search}">
  <div class="finding-head">
    <span class="badge badge-{sev}">{sev}</span>
    <span class="finding-type">{ftype}</span>
    {_method_pill(f)}{_status_pill(f.get("status"))}
  </div>
  <div class="finding-url">
    <a href="{url}" target="_blank" rel="noopener">{url}</a>
    <button class="copy-btn" onclick="copyURL('{url}')" title="Copy">⎘</button>
  </div>
  <div class="finding-reason">{reason}</div>
  {_signals_html(f)}{toggle}{code}
</div>"""


def render_html(results: list[dict], target: str, elapsed: float,
                req_count: int = 0) -> str:
    counts = {s: sum(1 for r in results if r.get("severity") == s)
              for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
    sorted_r = sorted(results, key=lambda r: SEVERITY_ORDER.get(r.get("severity", "INFO"), 9))
    findings_html = "\n".join(_render_finding(f, i) for i, f in enumerate(sorted_r)) \
        if sorted_r else '<div class="empty"><div class="empty-icon">🎉</div>No findings — clean scan!</div>'

    return (HTML
            .replace("{{total}}",         str(len(results)))
            .replace("{{critical}}",      str(counts["CRITICAL"]))
            .replace("{{high}}",          str(counts["HIGH"]))
            .replace("{{medium}}",        str(counts["MEDIUM"]))
            .replace("{{low}}",           str(counts["LOW"]))
            .replace("{{scan_time}}",     f"{elapsed:.0f}s")
            .replace("{{req_count}}",     str(req_count))
            .replace("{{date}}",          datetime.now().strftime("%Y-%m-%d %H:%M"))
            .replace("{{findings_html}}", findings_html)
            .replace("{{findings_json}}", json.dumps(sorted_r)))


def print_terminal_summary(results: list[dict], target: str,
                            elapsed: float, req_count: int = 0):
    sorted_r = sorted(results, key=lambda r: SEVERITY_ORDER.get(r.get("severity","INFO"), 9))
    t = Table(title=f"\n[bold]BAC Hunter v3.0 — {target}[/bold]",
              box=box.ROUNDED, border_style="dim white",
              show_header=True, header_style="bold cyan")
    t.add_column("Sev",    width=10)
    t.add_column("Type",   width=28)
    t.add_column("URL / Detail", no_wrap=False)
    t.add_column("Status", width=8)

    for r in sorted_r:
        sev = r.get("severity", "INFO")
        col = _SEV_RICH.get(sev, "white")
        t.add_row(
            f"[{col}]{sev}[/{col}]",
            r.get("type", ""),
            r.get("url") or r.get("reason", ""),
            str(r.get("status") or "—"),
        )
    console.print(t)

    counts = {s: sum(1 for r in results if r.get("severity") == s)
              for s in ["CRITICAL","HIGH","MEDIUM","LOW"]}
    console.print(
        f"\n[bold]Summary:[/bold] {len(results)} findings | "
        f"[red]CRIT {counts['CRITICAL']}[/red] | "
        f"[yellow]HIGH {counts['HIGH']}[/yellow] | "
        f"[bright_yellow]MED {counts['MEDIUM']}[/bright_yellow] | "
        f"[green]LOW {counts['LOW']}[/green]  "
        f"[dim]{elapsed:.1f}s · {req_count} requests[/dim]\n"
    )


def save_reports(results: list[dict], target: str, elapsed: float,
                 req_count: int = 0, out_dir: str = "reports") -> tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    html_path = os.path.join(out_dir, f"bac_{ts}.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(render_html(results, target, elapsed, req_count))

    json_path = os.path.join(out_dir, f"bac_{ts}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return html_path, json_path
