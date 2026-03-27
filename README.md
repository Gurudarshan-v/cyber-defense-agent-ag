# Autonomous Cyber Defense Agent v2

Full-stack autonomous security agent with web dashboard.

## Quick Start

```bash
# 1. Install dependencies
pip install fastapi uvicorn websockets pydantic

# 2. Run the web server
python web_server.py

# 3. Open in Chrome
http://localhost:8000
```

## Project Structure

```
cyberdefense/
├── core/
│   └── agent.py              # Agent orchestrator + data models
├── detectors/
│   └── detection_engine.py   # 7 detectors
│       ├── SignatureDetector      (regex rules — SQLi, XSS, Cmd, Path, Malware, Ransomware…)
│       ├── AnomalyDetector        (sliding window — brute force, port scan, exfil, DoS)
│       ├── MLThreatDetector       (feature scoring — UA, ports, entropy, paths)
│       ├── BehavioralDetector     (kill-chain sequence detection)
│       ├── NetworkFlowDetector    (protocol anomalies, DNS tunneling, RAT ports)
│       ├── InsiderThreatDetector  (after-hours, mass download, sensitive files)
│       └── ZeroDayDetector        (shellcode patterns, payload anomalies)
├── responders/
│   └── responders.py         # 7 responders
│       ├── FirewallResponder      (block_ip, block_outbound, rate_limit)
│       ├── HostIsolationResponder (quarantine + EDR integration)
│       ├── WAFResponder           (dynamic nginx / modsec rules)
│       ├── ProcessKillResponder   (kill malicious PIDs)
│       ├── AccountResponder       (flag / disable user accounts)
│       ├── EscalationResponder    (Slack / PagerDuty webhook)
│       └── LoggingResponder       (catch-all audit logger)
├── intel/
│   └── collectors.py         # 6 collectors
│       ├── NetworkCollector       (pcap / simulated attack scenarios)
│       ├── SyslogCollector        (UDP syslog / auth events)
│       ├── EDRCollector           (endpoint process events)
│       ├── ThreatIntelCollector   (IOC feeds / known-bad IPs)
│       ├── WAFCollector           (WAF block logs)
│       └── CloudCollector         (AWS CloudTrail / Azure Monitor)
├── config/
│   └── ioc_list.json         # custom IOC file (optional)
├── web_server.py             # FastAPI + WebSocket + dashboard
├── main.py                   # CLI entry point
└── requirements.txt
```

## REST API

| Endpoint | Description |
|----------|-------------|
| `GET /` | Live dashboard (HTML) |
| `GET /api/summary` | Agent stats |
| `GET /api/alerts` | All alerts (filter: severity, category, resolved) |
| `GET /api/actions` | Response log |
| `GET /api/blocked-ips` | Firewall block list |
| `GET /api/isolated-hosts` | Quarantined hosts |
| `GET /api/threat-map` | Source IPs with severity |
| `GET /api/stats/timeline` | Alert counts by minute |
| `GET /api/stats/categories` | Alert counts by category |
| `POST /api/alerts/{id}/resolve` | Resolve an alert |
| `WS /ws` | WebSocket live feed (2s updates) |

## Detector Coverage

| Detector | Threats Covered |
|----------|----------------|
| Signature | SQLi, XSS, Cmd Injection, Path Traversal, C2 Beacon, Ransomware, Mimikatz, PsExec, Phishing, Slowloris |
| Anomaly | Brute Force, Port Scan, Data Exfiltration (50MB+), DoS Flood |
| ML | Suspicious UA/port/path, off-hours, high-entropy URLs |
| Behavioral | Kill-chain: recon→brute→login, scan→exfil |
| Network Flow | RAT ports, DNS tunneling, cleartext credentials |
| Insider Threat | After-hours login, mass download (1GB+), sensitive file access |
| Zero-Day | Shellcode (NOP sleds, jump chains), anomalous payloads |

## Deployment Options

### Local / Dev
```bash
python web_server.py
# http://localhost:8000
```

### Expose via ngrok
```bash
pip install ngrok
ngrok http 8000
# → public HTTPS URL
```

### Linux systemd service
```ini
[Unit]
Description=Cyber Defense Agent
After=network.target

[Service]
WorkingDirectory=/path/to/cyberdefense
ExecStart=python3 web_server.py
Restart=always

[Install]
WantedBy=multi-user.target
```

### Docker
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install fastapi uvicorn websockets pydantic
EXPOSE 8000
CMD ["python", "web_server.py"]
```
```bash
docker build -t cyberdefense .
docker run -p 8000:8000 cyberdefense
```

## Configuration

Edit `web_server.py` to change:
- `auto_threshold` — severity level for auto-execution (LOW/MEDIUM/HIGH/CRITICAL)
- `attack_rate` — simulation attack frequency (0.0–1.0)
- `dry_run=False` — actually execute firewall/isolation commands
- `webhook_url` — Slack/PagerDuty escalation webhook

## Extending

```python
# Custom detector
class MyDetector:
    async def analyze(self, event: Event) -> list[ThreatAlert]: ...

# Custom responder
class MyResponder:
    async def can_handle(self, action) -> bool: ...
    async def execute(self, action, alert) -> str: ...
```
