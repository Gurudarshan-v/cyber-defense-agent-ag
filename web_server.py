"""
Cyber Defense Agent — Web Server
FastAPI + WebSocket + embedded dashboard

pip install fastapi uvicorn websockets
python web_server.py
Open: http://localhost:8000
"""

import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core.agent import CyberDefenseAgent
from detectors.detection_engine import (
    SignatureDetector, AnomalyDetector, MLThreatDetector,
    BehavioralDetector, NetworkFlowDetector,
    InsiderThreatDetector, ZeroDayDetector,
)
from responders.responders import (
    FirewallResponder, HostIsolationResponder, WAFResponder,
    ProcessKillResponder, AccountResponder,
    EscalationResponder, LoggingResponder,
)
from intel.collectors import (
    NetworkCollector, SyslogCollector, EDRCollector,
    ThreatIntelCollector, WAFCollector, CloudCollector,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)-22s] %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("CDA.Web")

# ── Build Agent ──────────────────────────────────────────────

agent = CyberDefenseAgent(config={
    "auto_threshold":   "HIGH",
    "collect_interval": 1.5,
    "learn_interval":   60,
})

# Collectors
for col in [NetworkCollector(simulate=True, attack_rate=0.40),
            SyslogCollector(simulate=True),
            EDRCollector(simulate=True),
            ThreatIntelCollector(simulate=True),
            WAFCollector(simulate=True),
            CloudCollector(simulate=True)]:
    agent.register_collector(col)

# Detectors
for det in [SignatureDetector(), AnomalyDetector(window_seconds=60),
            MLThreatDetector(), BehavioralDetector(),
            NetworkFlowDetector(), InsiderThreatDetector(), ZeroDayDetector()]:
    agent.register_detector(det)

# Responders
for resp in [FirewallResponder(dry_run=True),
             HostIsolationResponder(dry_run=True),
             WAFResponder(dry_run=True),
             ProcessKillResponder(dry_run=True),
             AccountResponder(dry_run=True),
             EscalationResponder(),
             LoggingResponder()]:
    agent.register_responder(resp)

# ── FastAPI ──────────────────────────────────────────────────

app = FastAPI(title="Cyber Defense Agent", version="2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

ws_clients: list[WebSocket] = []


@app.on_event("startup")
async def startup():
    asyncio.create_task(agent.start())
    asyncio.create_task(_broadcast_loop())
    logger.info("Agent started. Dashboard: http://localhost:8000")


# ── REST API ─────────────────────────────────────────────────

@app.get("/api/summary")
def api_summary():
    return agent.summary()


@app.get("/api/alerts")
def api_alerts(
    limit:    int = Query(50, ge=1, le=500),
    severity: str = Query(None),
    category: str = Query(None),
    resolved: bool = Query(None),
):
    alerts = agent.get_alerts(limit=limit, severity=severity,
                               category=category, resolved=resolved)
    return [_serialize_alert(a) for a in alerts]


@app.get("/api/actions")
def api_actions(limit: int = Query(50, ge=1, le=500)):
    return [_serialize_action(a) for a in reversed(agent.action_log[-limit:])]


@app.get("/api/blocked-ips")
def api_blocked():
    return sorted(agent.blocked_ips)


@app.get("/api/isolated-hosts")
def api_isolated():
    return sorted(agent.isolated_hosts)


class ResolveRequest(BaseModel):
    false_positive: bool = False
    notes: str = ""


@app.post("/api/alerts/{alert_id}/resolve")
def api_resolve(alert_id: str, body: ResolveRequest):
    ok = agent.resolve_alert(alert_id, body.false_positive, body.notes)
    if not ok:
        raise HTTPException(404, "Alert not found")
    return {"status": "resolved", "alert_id": alert_id}


@app.get("/api/threat-map")
def api_threat_map():
    """Return recent source IPs with severity for map visualization."""
    seen = {}
    for a in list(agent.alert_history)[-200:]:
        ip = a.event.source_ip
        if ip not in seen or a.severity.value > seen[ip]["severity_val"]:
            seen[ip] = {
                "ip": ip,
                "severity": a.severity.name,
                "severity_val": a.severity.value,
                "category": a.category.value,
                "count": seen.get(ip, {}).get("count", 0) + 1,
            }
    return list(seen.values())


@app.get("/api/stats/timeline")
def api_timeline():
    """Alert counts bucketed by minute for the last 30 min."""
    from collections import defaultdict
    buckets: dict[str, dict] = defaultdict(lambda: {"LOW":0,"MEDIUM":0,"HIGH":0,"CRITICAL":0})
    for a in agent.alert_history:
        key = a.created_at.strftime("%H:%M")
        buckets[key][a.severity.name] += 1
    return [{"time": k, **v} for k, v in sorted(buckets.items())[-30:]]


@app.get("/api/stats/categories")
def api_categories():
    from collections import Counter
    counts = Counter(a.category.value for a in agent.alert_history)
    return [{"category": k, "count": v} for k, v in counts.most_common(20)]


# ── WebSocket ────────────────────────────────────────────────

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    ws_clients.append(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        if ws in ws_clients:
            ws_clients.remove(ws)


async def _broadcast_loop():
    while True:
        await asyncio.sleep(2)
        if not ws_clients:
            continue
        # Recent alerts (last 5)
        recent = [_serialize_alert(a) for a in agent.get_alerts(limit=5)]
        payload = json.dumps({
            "type":    "update",
            "summary": agent.summary(),
            "recent_alerts": recent,
            "ts":      datetime.now().isoformat(),
        }, default=str)
        dead = []
        for ws in ws_clients:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in ws_clients:
                ws_clients.remove(ws)


# ── Serializers ──────────────────────────────────────────────

def _serialize_alert(a) -> dict:
    return {
        "alert_id":    a.alert_id,
        "category":    a.category.value,
        "severity":    a.severity.name,
        "confidence":  round(a.confidence, 3),
        "source_ip":   a.event.source_ip,
        "dest_ip":     a.event.dest_ip,
        "event_type":  a.event.event_type,
        "description": a.description,
        "mitre_ttps":  a.mitre_ttps,
        "created_at":  a.created_at.isoformat(),
        "resolved":    a.resolved,
        "false_positive": a.false_positive,
        "notes":       a.notes,
        "source":      a.event.source,
    }


def _serialize_action(a) -> dict:
    return {
        "action_type": a.action_type,
        "target":      a.target,
        "reason":      a.reason,
        "alert_id":    a.alert_id,
        "auto_execute": a.auto_execute,
        "executed":    a.executed,
        "result":      a.result,
        "timestamp":   a.timestamp.isoformat(),
    }


# ── Dashboard HTML ───────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return DASHBOARD_HTML


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberDefense Agent</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root {
  --bg0:#050810;--bg1:#0b0f1a;--bg2:#111827;--bg3:#1a2235;
  --border:#1e2d47;--border2:#2a3f5f;
  --text:#e2e8f0;--muted:#64748b;--dim:#94a3b8;
  --green:#10b981;--yellow:#f59e0b;--red:#ef4444;--blue:#3b82f6;
  --cyan:#06b6d4;--purple:#8b5cf6;--orange:#f97316;--pink:#ec4899;
  --critical:#ff2d55;--high:#ff9500;--medium:#ffd60a;--low:#30d158;
  --font-mono:'JetBrains Mono',monospace;
  --font-sans:'Syne',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:var(--bg0);color:var(--text);font-family:var(--font-mono);overflow:hidden}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:var(--bg1)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}

/* Layout */
.shell{display:grid;grid-template-rows:52px 1fr;height:100vh}
.topbar{display:flex;align-items:center;gap:16px;padding:0 20px;background:var(--bg1);border-bottom:1px solid var(--border);z-index:100}
.topbar .logo{font-family:var(--font-sans);font-size:15px;font-weight:800;letter-spacing:.05em;color:#fff;white-space:nowrap}
.topbar .logo span{color:var(--cyan)}
.status-pill{display:flex;align-items:center;gap:6px;font-size:11px;padding:4px 10px;border-radius:20px;background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.3);color:var(--green)}
.status-pill .dot{width:7px;height:7px;border-radius:50%;background:var(--green);animation:blink 1.4s ease-in-out infinite}
@keyframes blink{0%,100%{opacity:1;box-shadow:0 0 6px var(--green)}50%{opacity:.4;box-shadow:none}}
.status-pill.offline{background:rgba(239,68,68,.1);border-color:rgba(239,68,68,.3);color:var(--red)}
.status-pill.offline .dot{background:var(--red);animation:none}
.topbar-right{margin-left:auto;display:flex;align-items:center;gap:12px}
.uptime{font-size:11px;color:var(--muted)}
#clock{font-size:12px;color:var(--dim);font-weight:500}

.body{display:grid;grid-template-columns:200px 1fr 340px;height:100%;overflow:hidden}

/* Sidebar */
.sidebar{background:var(--bg1);border-right:1px solid var(--border);display:flex;flex-direction:column;padding:12px 0;overflow-y:auto}
.nav-section{padding:0 12px;margin-bottom:4px}
.nav-label{font-size:9px;letter-spacing:.12em;color:var(--muted);text-transform:uppercase;padding:8px 8px 4px}
.nav-item{display:flex;align-items:center;gap:10px;padding:7px 8px;border-radius:6px;cursor:pointer;font-size:11px;color:var(--dim);transition:all .15s;border:1px solid transparent}
.nav-item:hover{background:var(--bg2);color:var(--text)}
.nav-item.active{background:rgba(59,130,246,.1);color:var(--blue);border-color:rgba(59,130,246,.2)}
.nav-item .icon{width:16px;text-align:center;font-size:13px}
.nav-badge{margin-left:auto;font-size:9px;padding:2px 6px;border-radius:10px;background:var(--critical);color:#fff;font-weight:700;min-width:18px;text-align:center}

/* Main content */
.main{overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:14px}

/* Stat cards */
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.stat-card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;position:relative;overflow:hidden;transition:border-color .2s}
.stat-card::before{content:'';position:absolute;inset:0;opacity:.05;pointer-events:none}
.stat-card.c-green::before{background:linear-gradient(135deg,var(--green),transparent)}
.stat-card.c-red::before{background:linear-gradient(135deg,var(--red),transparent)}
.stat-card.c-blue::before{background:linear-gradient(135deg,var(--blue),transparent)}
.stat-card.c-yellow::before{background:linear-gradient(135deg,var(--yellow),transparent)}
.stat-card.c-purple::before{background:linear-gradient(135deg,var(--purple),transparent)}
.stat-card.c-cyan::before{background:linear-gradient(135deg,var(--cyan),transparent)}
.stat-card:hover{border-color:var(--border2)}
.stat-label{font-size:9px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
.stat-value{font-size:26px;font-weight:700;line-height:1;font-family:var(--font-sans)}
.stat-value.c-green{color:var(--green)}
.stat-value.c-red{color:var(--red)}
.stat-value.c-blue{color:var(--blue)}
.stat-value.c-yellow{color:var(--yellow)}
.stat-value.c-purple{color:var(--purple)}
.stat-value.c-cyan{color:var(--cyan)}
.stat-sub{font-size:10px;color:var(--muted);margin-top:4px}

/* Panels */
.panel{background:var(--bg2);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.panel-hdr{display:flex;align-items:center;gap:8px;padding:10px 14px;border-bottom:1px solid var(--border);font-size:11px;font-weight:500;color:var(--dim);letter-spacing:.06em}
.panel-hdr .dot-accent{width:6px;height:6px;border-radius:50%}
.panel-body{overflow-y:auto;max-height:260px}

/* Tables */
table{width:100%;border-collapse:collapse;font-size:11px}
th{padding:7px 10px;text-align:left;font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);background:var(--bg1);font-weight:500;position:sticky;top:0;z-index:1}
td{padding:6px 10px;border-top:1px solid rgba(255,255,255,.04);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:180px}
tr:hover td{background:rgba(255,255,255,.02)}

/* Severity badges */
.badge{display:inline-flex;align-items:center;gap:4px;padding:2px 7px;border-radius:4px;font-size:9px;font-weight:700;letter-spacing:.06em}
.badge::before{content:'';display:inline-block;width:5px;height:5px;border-radius:50%}
.badge.CRITICAL{background:rgba(255,45,85,.15);color:var(--critical)}
.badge.CRITICAL::before{background:var(--critical);box-shadow:0 0 4px var(--critical)}
.badge.HIGH{background:rgba(255,149,0,.15);color:var(--high)}
.badge.HIGH::before{background:var(--high)}
.badge.MEDIUM{background:rgba(255,214,10,.12);color:var(--medium)}
.badge.MEDIUM::before{background:var(--medium)}
.badge.LOW{background:rgba(48,209,88,.12);color:var(--low)}
.badge.LOW::before{background:var(--low)}

.cat-tag{display:inline-block;padding:2px 6px;border-radius:3px;font-size:9px;background:rgba(59,130,246,.1);color:var(--blue);border:1px solid rgba(59,130,246,.2)}
.src-tag{font-size:9px;padding:1px 5px;border-radius:3px;background:var(--bg3);color:var(--muted)}

.ip{font-family:var(--font-mono);font-size:10px;color:var(--cyan)}
.conf{font-size:10px;color:var(--dim)}
code{font-family:var(--font-mono);font-size:10px;background:var(--bg3);padding:1px 4px;border-radius:3px;color:var(--dim)}

/* Charts row */
.charts-row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.chart-wrap{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px}
.chart-title{font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:10px}
.chart-wrap canvas{max-height:160px}

/* Right panel */
.right{background:var(--bg1);border-left:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden}
.right-section{border-bottom:1px solid var(--border);flex-shrink:0}
.right-section:last-child{border-bottom:none;flex:1;overflow:hidden}
.section-hdr{display:flex;align-items:center;gap:8px;padding:10px 14px;font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.section-body{padding:0 12px 12px;overflow-y:auto;max-height:200px}

/* Live feed */
.feed-item{display:flex;gap:8px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:10px;animation:fadeIn .3s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}
.feed-time{color:var(--muted);white-space:nowrap;min-width:44px}
.feed-body{flex:1;overflow:hidden}
.feed-desc{color:var(--dim);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* Action log */
.action-item{padding:5px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:10px}
.action-type{display:inline-block;padding:1px 6px;border-radius:3px;font-size:9px;font-weight:600;margin-bottom:2px}
.action-type.block_ip{background:rgba(239,68,68,.15);color:var(--red)}
.action-type.isolate_host{background:rgba(139,92,246,.15);color:var(--purple)}
.action-type.rate_limit_ip{background:rgba(245,158,11,.15);color:var(--yellow)}
.action-type.patch_waf_rule{background:rgba(6,182,212,.15);color:var(--cyan)}
.action-type.escalate{background:rgba(255,45,85,.2);color:var(--critical)}
.action-type.log_and_monitor{background:rgba(100,116,139,.15);color:var(--muted)}
.action-type.flag_account{background:rgba(249,115,22,.15);color:var(--orange)}
.action-result{color:var(--muted);font-size:9px;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.exec-dot{display:inline-block;width:5px;height:5px;border-radius:50%;margin-right:3px}
.exec-dot.yes{background:var(--green)}
.exec-dot.no{background:var(--muted)}

/* Threat summary mini cards */
.mini-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px;padding:10px 12px}
.mini-card{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:8px 10px}
.mini-label{font-size:9px;color:var(--muted);margin-bottom:3px}
.mini-value{font-size:16px;font-weight:700;font-family:var(--font-sans)}

/* Resolve btn */
.resolve-btn{padding:2px 6px;font-size:9px;font-family:var(--font-mono);background:transparent;border:1px solid var(--border2);color:var(--muted);border-radius:3px;cursor:pointer;transition:all .15s}
.resolve-btn:hover{background:var(--bg3);color:var(--text);border-color:var(--green)}

/* TTP pill */
.ttp{display:inline-block;font-size:9px;padding:1px 5px;background:rgba(139,92,246,.12);color:var(--purple);border-radius:3px;margin:1px;border:1px solid rgba(139,92,246,.2)}

/* Scrollable alert table wrapper */
.alert-table-wrap{max-height:300px;overflow-y:auto}

/* Tabs */
.tabs{display:flex;gap:2px;padding:8px 12px;background:var(--bg1);border-bottom:1px solid var(--border)}
.tab{padding:4px 10px;border-radius:4px;font-size:10px;cursor:pointer;color:var(--muted);border:1px solid transparent;transition:all .15s}
.tab.active{background:rgba(59,130,246,.1);color:var(--blue);border-color:rgba(59,130,246,.2)}
.tab:hover:not(.active){background:var(--bg2);color:var(--dim)}
.tab-content{display:none}
.tab-content.active{display:block}

/* Blinking new */
@keyframes flash{0%,100%{background:transparent}50%{background:rgba(59,130,246,.08)}}
.new-row{animation:flash .6s}
</style>
</head>
<body>
<div class="shell">

<!-- Topbar -->
<div class="topbar">
  <div class="logo">CYBER<span>DEFENSE</span> AGENT</div>
  <div class="status-pill offline" id="status-pill">
    <div class="dot"></div>
    <span id="status-text">Connecting</span>
  </div>
  <div style="width:1px;height:20px;background:var(--border);margin:0 4px"></div>
  <div style="font-size:10px;color:var(--muted)">Auto-threshold: <span style="color:var(--high);font-weight:600">HIGH</span></div>
  <div class="topbar-right">
    <div class="uptime">Uptime: <span id="uptime-val">—</span></div>
    <div id="clock">—</div>
  </div>
</div>

<div class="body">

<!-- Sidebar -->
<div class="sidebar">
  <div class="nav-section">
    <div class="nav-label">Views</div>
    <div class="nav-item active" onclick="showView('overview')">
      <span class="icon">⬡</span> Overview
    </div>
    <div class="nav-item" onclick="showView('alerts')">
      <span class="icon">⚑</span> Alerts
      <span class="nav-badge" id="badge-alerts">0</span>
    </div>
    <div class="nav-item" onclick="showView('actions')">
      <span class="icon">⚡</span> Actions
    </div>
    <div class="nav-item" onclick="showView('network')">
      <span class="icon">◎</span> Network
    </div>
  </div>

  <div class="nav-section">
    <div class="nav-label">Detectors</div>
    <div class="nav-item" style="pointer-events:none">
      <span class="icon" style="color:var(--green)">●</span> Signature
    </div>
    <div class="nav-item" style="pointer-events:none">
      <span class="icon" style="color:var(--green)">●</span> Anomaly
    </div>
    <div class="nav-item" style="pointer-events:none">
      <span class="icon" style="color:var(--green)">●</span> ML Threat
    </div>
    <div class="nav-item" style="pointer-events:none">
      <span class="icon" style="color:var(--green)">●</span> Behavioral
    </div>
    <div class="nav-item" style="pointer-events:none">
      <span class="icon" style="color:var(--green)">●</span> Net Flow
    </div>
    <div class="nav-item" style="pointer-events:none">
      <span class="icon" style="color:var(--green)">●</span> Insider
    </div>
    <div class="nav-item" style="pointer-events:none">
      <span class="icon" style="color:var(--green)">●</span> Zero-Day
    </div>
  </div>

  <div class="nav-section" style="margin-top:auto">
    <div class="nav-label">Sources</div>
    <div class="nav-item" style="pointer-events:none;font-size:10px">
      <span class="icon">◌</span> Network
    </div>
    <div class="nav-item" style="pointer-events:none;font-size:10px">
      <span class="icon">◌</span> Syslog
    </div>
    <div class="nav-item" style="pointer-events:none;font-size:10px">
      <span class="icon">◌</span> EDR
    </div>
    <div class="nav-item" style="pointer-events:none;font-size:10px">
      <span class="icon">◌</span> Threat Intel
    </div>
    <div class="nav-item" style="pointer-events:none;font-size:10px">
      <span class="icon">◌</span> WAF
    </div>
    <div class="nav-item" style="pointer-events:none;font-size:10px">
      <span class="icon">◌</span> Cloud
    </div>
  </div>
</div>

<!-- Main -->
<div class="main" id="main">

  <!-- OVERVIEW VIEW -->
  <div id="view-overview" class="tab-content active">

    <div class="stat-grid">
      <div class="stat-card c-blue">
        <div class="stat-label">Events Processed</div>
        <div class="stat-value c-blue" id="stat-events">0</div>
        <div class="stat-sub">total ingested</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-label">Alerts Raised</div>
        <div class="stat-value c-red" id="stat-alerts">0</div>
        <div class="stat-sub">threats detected</div>
      </div>
      <div class="stat-card c-yellow">
        <div class="stat-label">Actions Taken</div>
        <div class="stat-value c-yellow" id="stat-actions">0</div>
        <div class="stat-sub">auto-responses</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-label">IPs Blocked</div>
        <div class="stat-value c-purple" id="stat-blocked">0</div>
        <div class="stat-sub">firewall rules</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-label">Hosts Isolated</div>
        <div class="stat-value c-green" id="stat-isolated">0</div>
        <div class="stat-sub">quarantined</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-label">False Positives</div>
        <div class="stat-value c-cyan" id="stat-fp">0</div>
        <div class="stat-sub">ML feedback</div>
      </div>
      <div class="stat-card c-yellow">
        <div class="stat-label">Pending Review</div>
        <div class="stat-value c-yellow" id="stat-pending">0</div>
        <div class="stat-sub">analyst queue</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-label">Critical Alerts</div>
        <div class="stat-value c-red" id="stat-critical">0</div>
        <div class="stat-sub">needs attention</div>
      </div>
    </div>

    <div class="charts-row">
      <div class="chart-wrap">
        <div class="chart-title">Alert Timeline</div>
        <canvas id="timeline-chart"></canvas>
      </div>
      <div class="chart-wrap">
        <div class="chart-title">Threat Categories</div>
        <canvas id="category-chart"></canvas>
      </div>
    </div>

    <div class="panel">
      <div class="panel-hdr">
        <div class="dot-accent" style="background:var(--red)"></div>
        RECENT ALERTS
      </div>
      <div class="alert-table-wrap" id="overview-alert-body">
        <table>
          <thead><tr>
            <th>Time</th><th>Severity</th><th>Category</th>
            <th>Source IP</th><th>Confidence</th><th>Source</th><th>Description</th>
          </tr></thead>
          <tbody id="overview-alert-rows">
            <tr><td colspan="7" style="text-align:center;color:var(--muted);padding:20px">Waiting for threats…</td></tr>
          </tbody>
        </table>
      </div>
    </div>

  </div>

  <!-- ALERTS VIEW -->
  <div id="view-alerts" class="tab-content">
    <div style="display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap">
      <select id="filter-severity" onchange="loadAlerts()" style="background:var(--bg2);border:1px solid var(--border);color:var(--text);padding:5px 8px;border-radius:5px;font-family:var(--font-mono);font-size:11px">
        <option value="">All Severities</option>
        <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
      </select>
      <select id="filter-category" onchange="loadAlerts()" style="background:var(--bg2);border:1px solid var(--border);color:var(--text);padding:5px 8px;border-radius:5px;font-family:var(--font-mono);font-size:11px">
        <option value="">All Categories</option>
        <option value="brute_force">Brute Force</option>
        <option value="port_scan">Port Scan</option>
        <option value="sql_injection">SQL Injection</option>
        <option value="xss">XSS</option>
        <option value="command_injection">Command Injection</option>
        <option value="malware">Malware</option>
        <option value="ransomware">Ransomware</option>
        <option value="data_exfiltration">Data Exfiltration</option>
        <option value="lateral_movement">Lateral Movement</option>
        <option value="privilege_escalation">Privilege Escalation</option>
        <option value="insider_threat">Insider Threat</option>
        <option value="zero_day">Zero-Day</option>
      </select>
      <button onclick="loadAlerts()" style="background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.3);color:var(--blue);padding:5px 12px;border-radius:5px;font-family:var(--font-mono);font-size:11px;cursor:pointer">Refresh</button>
    </div>
    <div class="panel">
      <div class="alert-table-wrap" style="max-height:none">
        <table>
          <thead><tr>
            <th>Time</th><th>Severity</th><th>Category</th>
            <th>Source IP</th><th>Dest IP</th><th>Conf</th>
            <th>TTPs</th><th>Source</th><th>Action</th>
          </tr></thead>
          <tbody id="alerts-rows">
            <tr><td colspan="9" style="text-align:center;color:var(--muted);padding:20px">Loading…</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ACTIONS VIEW -->
  <div id="view-actions" class="tab-content">
    <div class="panel">
      <div class="panel-hdr"><div class="dot-accent" style="background:var(--yellow)"></div>RESPONSE LOG</div>
      <div class="alert-table-wrap" style="max-height:none">
        <table>
          <thead><tr>
            <th>Action</th><th>Target</th><th>Alert</th>
            <th>Auto</th><th>Executed</th><th>Result</th><th>Time</th>
          </tr></thead>
          <tbody id="actions-rows">
            <tr><td colspan="7" style="text-align:center;color:var(--muted);padding:20px">No actions yet…</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- NETWORK VIEW -->
  <div id="view-network" class="tab-content">
    <div class="stat-grid" style="grid-template-columns:repeat(3,1fr)">
      <div class="stat-card c-red"><div class="stat-label">Blocked IPs</div><div class="stat-value c-red" id="net-blocked">0</div></div>
      <div class="stat-card c-purple"><div class="stat-label">Isolated Hosts</div><div class="stat-value c-purple" id="net-isolated">0</div></div>
      <div class="stat-card c-cyan"><div class="stat-label">WAF Rules</div><div class="stat-value c-cyan" id="net-waf">0</div></div>
    </div>
    <div class="panel" style="margin-top:10px">
      <div class="panel-hdr"><div class="dot-accent" style="background:var(--red)"></div>BLOCKED IPs</div>
      <div class="panel-body" id="blocked-list" style="padding:10px 14px;max-height:140px;overflow-y:auto;display:flex;flex-wrap:wrap;gap:6px">
        <span style="color:var(--muted);font-size:11px">None yet</span>
      </div>
    </div>
    <div class="panel" style="margin-top:10px">
      <div class="panel-hdr"><div class="dot-accent" style="background:var(--purple)"></div>ISOLATED HOSTS</div>
      <div class="panel-body" id="isolated-list" style="padding:10px 14px;max-height:140px;overflow-y:auto;display:flex;flex-wrap:wrap;gap:6px">
        <span style="color:var(--muted);font-size:11px">None yet</span>
      </div>
    </div>
    <div class="panel" style="margin-top:10px">
      <div class="panel-hdr"><div class="dot-accent" style="background:var(--blue)"></div>THREAT MAP (by Source IP)</div>
      <div id="threat-map-list" style="padding:10px 14px;max-height:200px;overflow-y:auto"></div>
    </div>
  </div>

</div>

<!-- Right Panel -->
<div class="right">

  <div class="right-section">
    <div class="section-hdr"><span style="color:var(--red)">■</span> LIVE FEED</div>
    <div class="section-body" id="live-feed" style="max-height:220px;padding:0 12px 8px">
      <div style="color:var(--muted);font-size:11px;padding:8px 0">Waiting for events…</div>
    </div>
  </div>

  <div class="right-section">
    <div class="section-hdr"><span style="color:var(--yellow)">■</span> RESPONSE ACTIONS</div>
    <div class="section-body" id="action-feed" style="max-height:200px;padding:0 12px 8px">
      <div style="color:var(--muted);font-size:11px;padding:8px 0">No actions yet…</div>
    </div>
  </div>

  <div class="right-section" style="flex:1;overflow:hidden">
    <div class="section-hdr"><span style="color:var(--purple)">■</span> THREAT BREAKDOWN</div>
    <div class="mini-grid" id="mini-stats">
      <div class="mini-card"><div class="mini-label">Critical</div><div class="mini-value" style="color:var(--critical)" id="ms-critical">0</div></div>
      <div class="mini-card"><div class="mini-label">High</div><div class="mini-value" style="color:var(--high)" id="ms-high">0</div></div>
      <div class="mini-card"><div class="mini-label">Medium</div><div class="mini-value" style="color:var(--medium)" id="ms-medium">0</div></div>
      <div class="mini-card"><div class="mini-label">Low</div><div class="mini-value" style="color:var(--low)" id="ms-low">0</div></div>
    </div>
  </div>

</div>

</div>
</div>

<script>
// ── State ─────────────────────────────────────
let critCount=0,highCount=0,medCount=0,lowCount=0;
let timelineChart=null, catChart=null;
let lastActionCount=0;
const feedMax=30;

// ── Clock ─────────────────────────────────────
function tick(){document.getElementById('clock').textContent=new Date().toLocaleTimeString();}
setInterval(tick,1000); tick();

// ── View navigation ──────────────────────────
function showView(v){
  document.querySelectorAll('.tab-content').forEach(e=>e.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(e=>e.classList.remove('active'));
  document.getElementById('view-'+v).classList.add('active');
  event.currentTarget.classList.add('active');
  if(v==='alerts') loadAlerts();
  if(v==='actions') loadActions();
  if(v==='network') loadNetwork();
}

// ── Charts ────────────────────────────────────
function initCharts(){
  const cOpts={responsive:true,maintainAspectRatio:true,plugins:{legend:{display:false}},
    scales:{x:{ticks:{color:'#475569',font:{size:9},maxTicksLimit:8},grid:{color:'rgba(255,255,255,.03)'}},
            y:{ticks:{color:'#475569',font:{size:9}},grid:{color:'rgba(255,255,255,.05)'}}}};

  timelineChart=new Chart(document.getElementById('timeline-chart').getContext('2d'),{
    type:'line',
    data:{labels:[],datasets:[
      {label:'CRITICAL',data:[],borderColor:'#ff2d55',backgroundColor:'rgba(255,45,85,.08)',tension:.4,borderWidth:1.5,pointRadius:0,fill:true},
      {label:'HIGH',data:[],borderColor:'#ff9500',backgroundColor:'rgba(255,149,0,.06)',tension:.4,borderWidth:1.5,pointRadius:0,fill:true},
      {label:'MEDIUM',data:[],borderColor:'#ffd60a',backgroundColor:'transparent',tension:.4,borderWidth:1,pointRadius:0},
    ]},
    options:{...cOpts,plugins:{legend:{display:true,labels:{color:'#64748b',font:{size:9},boxWidth:10,padding:8}}}}
  });

  const catColors=['#3b82f6','#ef4444','#10b981','#f59e0b','#8b5cf6','#06b6d4','#f97316','#ec4899','#64748b','#22c55e'];
  catChart=new Chart(document.getElementById('category-chart').getContext('2d'),{
    type:'bar',
    data:{labels:[],datasets:[{data:[],backgroundColor:catColors,borderWidth:0,borderRadius:3}]},
    options:{...cOpts,indexAxis:'y',plugins:{legend:{display:false}}}
  });
}

async function refreshCharts(){
  try{
    const [tl,cats]=await Promise.all([
      fetch('/api/stats/timeline').then(r=>r.json()),
      fetch('/api/stats/categories').then(r=>r.json()),
    ]);
    if(tl.length){
      timelineChart.data.labels=tl.map(t=>t.time);
      timelineChart.data.datasets[0].data=tl.map(t=>t.CRITICAL||0);
      timelineChart.data.datasets[1].data=tl.map(t=>t.HIGH||0);
      timelineChart.data.datasets[2].data=tl.map(t=>t.MEDIUM||0);
      timelineChart.update('none');
    }
    if(cats.length){
      catChart.data.labels=cats.map(c=>c.category.replace(/_/g,' '));
      catChart.data.datasets[0].data=cats.map(c=>c.count);
      catChart.update('none');
    }
  }catch(e){}
}

// ── WebSocket ─────────────────────────────────
const ws=new WebSocket(`ws://${location.host}/ws`);
ws.onopen=()=>{
  const p=document.getElementById('status-pill');
  p.classList.remove('offline');
  document.getElementById('status-text').textContent='Live';
};
ws.onclose=()=>{
  document.getElementById('status-pill').classList.add('offline');
  document.getElementById('status-text').textContent='Disconnected';
};
ws.onmessage=e=>{
  const msg=JSON.parse(e.data);
  if(msg.type==='update'){
    updateStats(msg.summary);
    updateFeed(msg.recent_alerts||[]);
    updateMiniStats(msg.recent_alerts||[]);
  }
};

function updateStats(s){
  document.getElementById('stat-events').textContent=fmt(s.events_processed);
  document.getElementById('stat-alerts').textContent=fmt(s.alerts_raised);
  document.getElementById('stat-actions').textContent=fmt(s.actions_taken);
  document.getElementById('stat-blocked').textContent=fmt(s.blocked_ips||0);
  document.getElementById('stat-isolated').textContent=fmt(s.isolated_hosts||0);
  document.getElementById('stat-fp').textContent=fmt(s.false_positives||0);
  document.getElementById('stat-pending').textContent=fmt(s.pending_actions||0);
  document.getElementById('badge-alerts').textContent=fmt(s.alerts_raised);
  document.getElementById('uptime-val').textContent=fmtTime(s.uptime_seconds||0);
}

function updateFeed(alerts){
  if(!alerts.length) return;
  const feed=document.getElementById('live-feed');
  alerts.forEach(a=>{
    const el=document.createElement('div');
    el.className='feed-item';
    const t=new Date(a.created_at).toLocaleTimeString('en',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});
    el.innerHTML=`<div class="feed-time">${t}</div>
      <div class="feed-body">
        <div><span class="badge ${a.severity}">${a.severity}</span> <span class="cat-tag">${a.category}</span></div>
        <div class="feed-desc">${a.source_ip} → ${a.description.slice(0,50)}</div>
      </div>`;
    feed.insertBefore(el, feed.firstChild);
    if(feed.children.length>feedMax) feed.removeChild(feed.lastChild);
  });

  // update overview table too
  updateOverviewTable(alerts);
  // update action feed
  loadActionFeed();
}

function updateMiniStats(alerts){
  for(const a of alerts){
    if(a.severity==='CRITICAL') critCount++;
    else if(a.severity==='HIGH') highCount++;
    else if(a.severity==='MEDIUM') medCount++;
    else lowCount++;
  }
  document.getElementById('ms-critical').textContent=critCount;
  document.getElementById('ms-high').textContent=highCount;
  document.getElementById('ms-medium').textContent=medCount;
  document.getElementById('ms-low').textContent=lowCount;
  document.getElementById('stat-critical').textContent=critCount;
}

function updateOverviewTable(alerts){
  const tb=document.getElementById('overview-alert-rows');
  if(!alerts.length) return;
  const rows=alerts.map(a=>`
    <tr class="new-row">
      <td>${new Date(a.created_at).toLocaleTimeString()}</td>
      <td><span class="badge ${a.severity}">${a.severity}</span></td>
      <td><span class="cat-tag">${a.category}</span></td>
      <td class="ip">${a.source_ip}</td>
      <td class="conf">${(a.confidence*100).toFixed(0)}%</td>
      <td><span class="src-tag">${a.source}</span></td>
      <td style="color:var(--muted)">${a.description.slice(0,55)}${a.description.length>55?'…':''}</td>
    </tr>`).join('');
  // Prepend new rows
  tb.innerHTML=rows+tb.innerHTML;
  // Trim to 50 rows
  while(tb.children.length>50) tb.removeChild(tb.lastChild);
}

// ── Alerts view ───────────────────────────────
async function loadAlerts(){
  const sev=document.getElementById('filter-severity')?.value||'';
  const cat=document.getElementById('filter-category')?.value||'';
  let url=`/api/alerts?limit=100`;
  if(sev) url+=`&severity=${sev}`;
  if(cat) url+=`&category=${cat}`;
  const data=await fetch(url).then(r=>r.json());
  const tb=document.getElementById('alerts-rows');
  if(!data.length){tb.innerHTML='<tr><td colspan="9" style="text-align:center;color:var(--muted);padding:20px">No alerts match filter</td></tr>';return;}
  tb.innerHTML=data.map(a=>`<tr>
    <td>${new Date(a.created_at).toLocaleTimeString()}</td>
    <td><span class="badge ${a.severity}">${a.severity}</span></td>
    <td><span class="cat-tag">${a.category}</span></td>
    <td class="ip">${a.source_ip}</td>
    <td class="ip">${a.dest_ip}</td>
    <td class="conf">${(a.confidence*100).toFixed(0)}%</td>
    <td>${(a.mitre_ttps||[]).map(t=>`<span class="ttp">${t}</span>`).join('')||'—'}</td>
    <td><span class="src-tag">${a.source}</span></td>
    <td>${a.resolved?'<span style="color:var(--green);font-size:10px">✓ done</span>':
      `<button class="resolve-btn" onclick="resolve('${a.alert_id}',false)">Resolve</button>`}</td>
  </tr>`).join('');
}

async function resolve(id,fp){
  await fetch(`/api/alerts/${id}/resolve`,{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({false_positive:fp,notes:''})});
  loadAlerts();
}

// ── Actions view ──────────────────────────────
async function loadActions(){
  const data=await fetch('/api/actions?limit=100').then(r=>r.json());
  const tb=document.getElementById('actions-rows');
  if(!data.length){tb.innerHTML='<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:20px">No actions yet</td></tr>';return;}
  tb.innerHTML=data.map(a=>`<tr>
    <td><span class="action-type ${a.action_type}">${a.action_type}</span></td>
    <td class="ip">${a.target}</td>
    <td><code>${a.alert_id}</code></td>
    <td>${a.auto_execute?'<span style="color:var(--green);font-size:10px">Auto</span>':'<span style="color:var(--muted);font-size:10px">Manual</span>'}</td>
    <td><span class="exec-dot ${a.executed?'yes':'no'}"></span>${a.executed?'Yes':'Pending'}</td>
    <td style="color:var(--muted);font-size:9px">${(a.result||'—').slice(0,40)}</td>
    <td>${new Date(a.timestamp).toLocaleTimeString()}</td>
  </tr>`).join('');
}

// ── Action feed (right panel) ─────────────────
async function loadActionFeed(){
  const data=await fetch('/api/actions?limit=10').then(r=>r.json());
  if(!data.length||data.length===lastActionCount) return;
  lastActionCount=data.length;
  const feed=document.getElementById('action-feed');
  feed.innerHTML=data.map(a=>`<div class="action-item">
    <span class="action-type ${a.action_type}">${a.action_type}</span>
    <span class="ip" style="margin-left:4px">${a.target}</span>
    <div class="action-result"><span class="exec-dot ${a.executed?'yes':'no'}"></span>${(a.result||'pending').slice(0,50)}</div>
  </div>`).join('');
}

// ── Network view ──────────────────────────────
async function loadNetwork(){
  const [blocked,isolated,threatMap]=await Promise.all([
    fetch('/api/blocked-ips').then(r=>r.json()),
    fetch('/api/isolated-hosts').then(r=>r.json()),
    fetch('/api/threat-map').then(r=>r.json()),
  ]);
  document.getElementById('net-blocked').textContent=blocked.length;
  document.getElementById('net-isolated').textContent=isolated.length;
  document.getElementById('stat-blocked').textContent=blocked.length;
  document.getElementById('stat-isolated').textContent=isolated.length;

  const bl=document.getElementById('blocked-list');
  bl.innerHTML=blocked.length?blocked.map(ip=>`<span class="ip" style="background:rgba(239,68,68,.1);padding:2px 6px;border-radius:3px">${ip}</span>`).join(''):'<span style="color:var(--muted);font-size:11px">None</span>';

  const il=document.getElementById('isolated-list');
  il.innerHTML=isolated.length?isolated.map(ip=>`<span class="ip" style="background:rgba(139,92,246,.1);padding:2px 6px;border-radius:3px">${ip}</span>`).join(''):'<span style="color:var(--muted);font-size:11px">None</span>';

  const ml=document.getElementById('threat-map-list');
  ml.innerHTML=threatMap.sort((a,b)=>b.severity_val-a.severity_val).slice(0,20).map(t=>`
    <div style="display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.03)">
      <span class="badge ${t.severity}" style="min-width:70px">${t.severity}</span>
      <span class="ip">${t.ip}</span>
      <span class="cat-tag">${t.category}</span>
      <span style="margin-left:auto;font-size:9px;color:var(--muted)">${t.count}×</span>
    </div>`).join('');
}

// ── Helpers ───────────────────────────────────
function fmt(n){return Number(n).toLocaleString()}
function fmtTime(s){
  const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),ss=s%60;
  return h?`${h}h ${m}m`:(m?`${m}m ${ss}s`:`${ss}s`);
}

// ── Init ──────────────────────────────────────
initCharts();
setInterval(refreshCharts, 5000);
refreshCharts();
setInterval(loadActionFeed, 3000);
</script>
</body>
</html>
"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
