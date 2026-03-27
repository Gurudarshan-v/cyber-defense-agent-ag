"""
Detection Engine
Signature + Anomaly + ML + Behavioral + Network + Insider Threat detectors
"""

import math
import re
import uuid
import logging
import random
from collections import defaultdict, deque
from datetime import datetime, timedelta
from core.agent import Event, ThreatAlert, ThreatCategory, Severity

logger = logging.getLogger("CDA.Detectors")


def _alert(event, category, severity, confidence, description, ttps=None) -> ThreatAlert:
    return ThreatAlert(
        alert_id    = str(uuid.uuid4())[:8],
        event       = event,
        category    = category,
        severity    = severity,
        confidence  = min(confidence, 1.0),
        description = description,
        mitre_ttps  = ttps or [],
    )


# ──────────────────────────────────────────────────────────────
# 1. Signature Detector — pattern matching on known attack signatures
# ──────────────────────────────────────────────────────────────

class SignatureDetector:
    RULES = [
        # Web attacks
        dict(id="S001", name="SQL injection",
             pattern=r"(?i)(union[\s+]+select|or[\s+]+1[\s]*=[\s]*1|drop[\s]+table|insert[\s]+into|select[\s]+\*[\s]+from|benchmark\(|sleep\(|waitfor[\s]+delay)",
             field="payload", category=ThreatCategory.SQL_INJECTION,
             severity=Severity.HIGH, confidence=0.92, ttps=["T1190"]),

        dict(id="S002", name="XSS attack",
             pattern=r"(?i)(<script[\s\S]*?>|javascript:|on\w+\s*=|<img[^>]+onerror|expression\s*\()",
             field="payload", category=ThreatCategory.XSS,
             severity=Severity.MEDIUM, confidence=0.88, ttps=["T1189"]),

        dict(id="S003", name="Command injection",
             pattern=r"(?i)(;[\s]*(ls|cat|id|whoami|wget|curl|bash|sh|python)|&&[\s]*(cat|id|ls)|\|[\s]*(id|whoami|uname)|\$\([\s]*id\s*\))",
             field="payload", category=ThreatCategory.COMMAND_INJECTION,
             severity=Severity.CRITICAL, confidence=0.95, ttps=["T1059", "T1190"]),

        dict(id="S004", name="Path traversal",
             pattern=r"(\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e|\/etc\/passwd|\/etc\/shadow|C:\\Windows\\System32)",
             field="url", category=ThreatCategory.PATH_TRAVERSAL,
             severity=Severity.HIGH, confidence=0.90, ttps=["T1083"]),

        # Malware / C2
        dict(id="S005", name="Malware C2 beacon",
             pattern=r"(\/c2\/beacon|\/gate\.php|\/panel\/|checkin\.aspx|\/bot\/|heartbeat\.php|\/report\/\d+)",
             field="url", category=ThreatCategory.MALWARE,
             severity=Severity.CRITICAL, confidence=0.96, ttps=["T1071.001", "T1095"]),

        dict(id="S006", name="Ransomware file extension",
             pattern=r"\.(locky|wcry|wncry|wncryt|cerber|crypt|enc|encrypted|locked|zepto|thor)$",
             field="filename", category=ThreatCategory.RANSOMWARE,
             severity=Severity.CRITICAL, confidence=0.98, ttps=["T1486"]),

        dict(id="S007", name="Ransomware note dropped",
             pattern=r"(?i)(how_to_decrypt|your_files_are_encrypted|readme_decrypt|how_to_recover|ransom_note)",
             field="filename", category=ThreatCategory.RANSOMWARE,
             severity=Severity.CRITICAL, confidence=0.97, ttps=["T1486"]),

        # Privilege escalation
        dict(id="S008", name="Privilege escalation command",
             pattern=r"(?i)(sudo[\s]+-i|chmod[\s]+[0-7]*7|passwd[\s]+root|net[\s]+localgroup[\s]+administrators|useradd|usermod[\s]+-aG[\s]+sudo)",
             field="command", category=ThreatCategory.PRIVILEGE_ESCALATION,
             severity=Severity.HIGH, confidence=0.88, ttps=["T1078", "T1548"]),

        dict(id="S009", name="SUID/GUID abuse",
             pattern=r"(?i)(find[\s]+\/[\s]+-perm[\s]+-[0-9]*[46]000|chmod[\s]+[0-9]*[46]755)",
             field="command", category=ThreatCategory.PRIVILEGE_ESCALATION,
             severity=Severity.HIGH, confidence=0.85, ttps=["T1548.001"]),

        # Lateral movement
        dict(id="S010", name="PsExec / lateral movement",
             pattern=r"(?i)(psexec|wmic.*\/node:|schtasks.*\/s[\s]|at[\s]+\\\\|sc[\s]+\\\\|winrm|evil-winrm)",
             field="command", category=ThreatCategory.LATERAL_MOVEMENT,
             severity=Severity.HIGH, confidence=0.87, ttps=["T1021.002", "T1570"]),

        dict(id="S011", name="Pass-the-hash / Mimikatz",
             pattern=r"(?i)(mimikatz|sekurlsa|lsadump|dcsync|golden[\s]+ticket|kerberoast|rubeus)",
             field="command", category=ThreatCategory.LATERAL_MOVEMENT,
             severity=Severity.CRITICAL, confidence=0.97, ttps=["T1550.002", "T1003"]),

        # Phishing
        dict(id="S012", name="Phishing URL pattern",
             pattern=r"(?i)(paypa[l1]|g[o0][o0]g[l1]e|micros[o0]ft|app[l1]e|amaz[o0]n|bank[o0]f|secure[\-]?login|verify[\-]?account)[\-\.](?!com$|net$|org$)",
             field="url", category=ThreatCategory.PHISHING,
             severity=Severity.HIGH, confidence=0.80, ttps=["T1566.002"]),

        # DoS patterns
        dict(id="S013", name="Slowloris / slow HTTP",
             pattern=r"(?i)(X-a:[\s]+b|slowloris|Connection:[\s]+keep-alive.*\r\n[\s]+\r\n$)",
             field="headers", category=ThreatCategory.DOS,
             severity=Severity.MEDIUM, confidence=0.75, ttps=["T1499"]),
    ]

    def __init__(self):
        self._compiled = [{**r, "_re": re.compile(r["pattern"])} for r in self.RULES]

    async def analyze(self, event: Event) -> list[ThreatAlert]:
        alerts = []
        for rule in self._compiled:
            val = event.raw_data.get(rule["field"], "")
            if not val:
                continue
            if rule["_re"].search(str(val)):
                alerts.append(_alert(event, rule["category"], rule["severity"],
                                     rule["confidence"],
                                     f"{rule['name']} — rule {rule['id']}",
                                     rule["ttps"]))
        return alerts


# ──────────────────────────────────────────────────────────────
# 2. Anomaly Detector — sliding window behavioral analysis
# ──────────────────────────────────────────────────────────────

class AnomalyDetector:
    def __init__(self, window_seconds: int = 60):
        self._window  = window_seconds
        self._events: dict[str, deque] = defaultdict(deque)     # ip → timestamps
        self._ports:  dict[str, set]   = defaultdict(set)        # ip → distinct dest ports
        self._bytes:  dict[str, int]   = defaultdict(int)        # ip → bytes out

    def _prune(self, ip: str):
        cutoff = datetime.now() - timedelta(seconds=self._window)
        while self._events[ip] and self._events[ip][0] < cutoff:
            self._events[ip].popleft()

    def _count(self, ip: str) -> int:
        self._prune(ip)
        self._events[ip].append(datetime.now())
        return len(self._events[ip])

    async def analyze(self, event: Event) -> list[ThreatAlert]:
        alerts = []
        src    = event.source_ip
        count  = self._count(src)
        raw    = event.raw_data

        # Brute force: repeated auth failures
        if event.event_type == "auth_failure" and count >= 10:
            sev = (Severity.CRITICAL if count >= 50 else
                   Severity.HIGH     if count >= 20 else Severity.MEDIUM)
            alerts.append(_alert(event, ThreatCategory.BRUTE_FORCE, sev,
                                 min(0.5 + count / 100, 0.99),
                                 f"Brute-force: {count} failures from {src} in {self._window}s",
                                 ["T1110"]))

        # Port scan
        if event.event_type == "connection_attempt":
            port = raw.get("dest_port", 0)
            self._ports[src].add(port)
            distinct = len(self._ports[src])
            if distinct >= 15:
                sev = Severity.CRITICAL if distinct >= 100 else (
                      Severity.HIGH if distinct >= 50 else Severity.MEDIUM)
                alerts.append(_alert(event, ThreatCategory.PORT_SCAN, sev,
                                     min(0.4 + distinct / 200, 0.95),
                                     f"Port scan: {distinct} distinct ports from {src}",
                                     ["T1046"]))

        # Large outbound — data exfiltration
        if event.event_type == "data_transfer":
            b = raw.get("bytes_out", 0)
            self._bytes[src] += b
            total = self._bytes[src]
            if total > 50_000_000:
                alerts.append(_alert(event, ThreatCategory.DATA_EXFILTRATION,
                                     Severity.HIGH, 0.82,
                                     f"Exfiltration: {total/1e6:.1f} MB outbound from {src}",
                                     ["T1041", "T1048"]))

        # Request flood — DoS
        if event.event_type in ("http_request", "connection_attempt") and count >= 200:
            alerts.append(_alert(event, ThreatCategory.DOS,
                                 Severity.HIGH, min(0.5 + count / 500, 0.95),
                                 f"DoS: {count} requests from {src} in {self._window}s",
                                 ["T1499"]))

        return alerts


# ──────────────────────────────────────────────────────────────
# 3. ML-Based Threat Detector — feature scoring
# ──────────────────────────────────────────────────────────────

class MLThreatDetector:
    SUSPECT_PORTS = {22, 23, 445, 1433, 3306, 3389, 4444, 5900,
                     6667, 8080, 8443, 9001, 31337, 65535}
    SUSPECT_UAS   = ["sqlmap", "nikto", "nmap", "masscan", "zgrab",
                     "python-requests/2.2", "go-http-client/1.1",
                     "dirbuster", "hydra", "metasploit", "burpsuite"]
    SUSPECT_PATHS = ["/admin", "/wp-admin", "/.env", "/.git", "/config",
                     "/backup", "/shell", "/cmd", "/phpmyadmin", "/manager"]

    def _features(self, event: Event) -> dict:
        raw = event.raw_data
        url = str(raw.get("url", ""))
        ua  = str(raw.get("user_agent", "")).lower()
        return {
            "suspect_port":    int(raw.get("dest_port", 0) in self.SUSPECT_PORTS),
            "suspect_ua":      int(any(s in ua for s in self.SUSPECT_UAS)),
            "off_hours":       int(event.timestamp.hour in range(1, 6)),
            "high_entropy":    int(self._entropy(url) > 4.2),
            "suspect_path":    int(any(url.startswith(p) for p in self.SUSPECT_PATHS)),
            "non_std_port":    int(raw.get("dest_port", 0) not in {80, 443, 53, 25, 587}),
            "large_payload":   int(raw.get("bytes_out", 0) > 10_000),
        }

    @staticmethod
    def _entropy(s: str) -> float:
        if not s: return 0.0
        freq = defaultdict(int)
        for c in s: freq[c] += 1
        n = len(s)
        return -sum((f/n) * math.log2(f/n) for f in freq.values())

    def _score(self, features: dict) -> float:
        W = {"suspect_port": 0.25, "suspect_ua": 0.30, "off_hours": 0.12,
             "high_entropy": 0.10, "suspect_path": 0.10, "non_std_port": 0.08,
             "large_payload": 0.05}
        return sum(v * W[k] for k, v in features.items())

    async def analyze(self, event: Event) -> list[ThreatAlert]:
        if event.event_type not in {"http_request", "connection_attempt"}:
            return []
        features = self._features(event)
        score    = self._score(features)
        if score < 0.30:
            return []
        active = [k for k, v in features.items() if v]
        sev = (Severity.CRITICAL if score >= 0.80 else
               Severity.HIGH     if score >= 0.60 else Severity.MEDIUM)
        return [_alert(event, ThreatCategory.UNKNOWN, sev, round(score, 3),
                       f"ML score {score:.2f} — signals: {', '.join(active)}",
                       ["T1190"])]


# ──────────────────────────────────────────────────────────────
# 4. Behavioral Detector — sequence / time-series analysis
# ──────────────────────────────────────────────────────────────

class BehavioralDetector:
    """Detects kill-chain patterns: recon → exploit → pivot → exfil"""

    def __init__(self, window_minutes: int = 15):
        self._window = window_minutes * 60
        self._history: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

    async def analyze(self, event: Event) -> list[ThreatAlert]:
        src = event.source_ip
        self._history[src].append((datetime.now(), event.event_type))
        return self._check_kill_chain(src, event)

    def _recent_types(self, src: str) -> set:
        cutoff = datetime.now() - timedelta(seconds=self._window)
        return {et for ts, et in self._history[src] if ts >= cutoff}

    def _check_kill_chain(self, src: str, event: Event) -> list[ThreatAlert]:
        alerts = []
        types  = self._recent_types(src)

        # Recon → Exploit → Auth = lateral movement chain
        if {"connection_attempt", "auth_failure", "auth_success"} <= types:
            alerts.append(_alert(event, ThreatCategory.LATERAL_MOVEMENT,
                                 Severity.HIGH, 0.83,
                                 f"Kill-chain: recon→brute→login from {src}",
                                 ["T1046", "T1110", "T1078"]))

        # Recon → large data transfer = exfiltration chain
        if {"connection_attempt", "data_transfer"} <= types:
            alerts.append(_alert(event, ThreatCategory.DATA_EXFILTRATION,
                                 Severity.HIGH, 0.78,
                                 f"Kill-chain: scan→exfil from {src}",
                                 ["T1046", "T1041"]))

        return alerts


# ──────────────────────────────────────────────────────────────
# 5. Network Flow Detector — protocol-level anomalies
# ──────────────────────────────────────────────────────────────

class NetworkFlowDetector:
    DANGEROUS_PORTS = {4444, 1234, 31337, 9001, 6667}   # common RAT / C2 ports

    def __init__(self):
        self._dns_queries: dict[str, list] = defaultdict(list)

    async def analyze(self, event: Event) -> list[ThreatAlert]:
        if event.event_type not in ("network_packet", "dns_query",
                                    "connection_attempt", "http_request"):
            return []
        alerts = []
        raw    = event.raw_data
        src    = event.source_ip

        # Cleartext on sensitive ports
        if (raw.get("dest_port") in {21, 23, 80} and
                raw.get("contains_credentials")):
            alerts.append(_alert(event, ThreatCategory.INSIDER_THREAT,
                                 Severity.MEDIUM, 0.70,
                                 "Credentials sent in cleartext",
                                 ["T1040"]))

        # Unexpected outbound to dangerous port
        if raw.get("dest_port") in self.DANGEROUS_PORTS:
            alerts.append(_alert(event, ThreatCategory.MALWARE,
                                 Severity.HIGH, 0.88,
                                 f"Connection to known RAT port {raw.get('dest_port')} from {src}",
                                 ["T1095", "T1071"]))

        # DNS tunneling: unusually long subdomain
        if event.event_type == "dns_query":
            domain = raw.get("query", "")
            parts  = domain.split(".")
            if parts and len(parts[0]) > 50:
                alerts.append(_alert(event, ThreatCategory.DATA_EXFILTRATION,
                                     Severity.HIGH, 0.82,
                                     f"DNS tunneling suspected — long subdomain from {src}",
                                     ["T1071.004"]))

        return alerts


# ──────────────────────────────────────────────────────────────
# 6. Insider Threat Detector
# ──────────────────────────────────────────────────────────────

class InsiderThreatDetector:
    def __init__(self):
        self._access_log: dict[str, list] = defaultdict(list)   # user → access times
        self._download_volume: dict[str, int] = defaultdict(int)

    async def analyze(self, event: Event) -> list[ThreatAlert]:
        if event.event_type not in ("file_access", "data_transfer",
                                    "auth_success", "print_job"):
            return []
        alerts = []
        raw    = event.raw_data
        user   = raw.get("username", event.source_ip)
        hour   = event.timestamp.hour

        # After-hours access
        if event.event_type == "auth_success" and hour in range(22, 6):
            alerts.append(_alert(event, ThreatCategory.INSIDER_THREAT,
                                 Severity.MEDIUM, 0.65,
                                 f"After-hours login: {user} at {event.timestamp:%H:%M}",
                                 ["T1078"]))

        # Mass download
        if event.event_type == "data_transfer":
            self._download_volume[user] += raw.get("bytes_out", 0)
            if self._download_volume[user] > 1_000_000_000:  # 1 GB
                alerts.append(_alert(event, ThreatCategory.INSIDER_THREAT,
                                     Severity.HIGH, 0.80,
                                     f"Mass download: {user} — {self._download_volume[user]/1e9:.1f} GB",
                                     ["T1048"]))

        # Sensitive file access
        sensitive = raw.get("file_path", "")
        if any(kw in sensitive.lower() for kw in
               ("salary", "password", "credentials", "backup", "secret", "private")):
            alerts.append(_alert(event, ThreatCategory.INSIDER_THREAT,
                                 Severity.HIGH, 0.75,
                                 f"Sensitive file accessed: {sensitive} by {user}",
                                 ["T1083"]))

        return alerts


# ──────────────────────────────────────────────────────────────
# 7. Zero-Day / Heuristic Detector
# ──────────────────────────────────────────────────────────────

class ZeroDayDetector:
    """
    Detects novel attacks by looking for generic exploit patterns:
    heap spray, shellcode-like byte sequences, abnormal binary payloads.
    """

    SHELLCODE_PATTERNS = [
        rb"\x90{10,}",                        # NOP sled
        rb"(\xeb.|\xe8.{4}|\xff\xe4|\xff\xd0)",  # common shellcode jumps
    ]

    def __init__(self):
        self._compiled = [re.compile(p) for p in self.SHELLCODE_PATTERNS]

    async def analyze(self, event: Event) -> list[ThreatAlert]:
        raw = event.raw_data
        payload = raw.get("raw_bytes", b"") or raw.get("payload", "")

        if isinstance(payload, str):
            payload = payload.encode(errors="replace")

        alerts = []
        for pat in self._compiled:
            if pat.search(payload):
                alerts.append(_alert(event, ThreatCategory.ZERO_DAY,
                                     Severity.CRITICAL, 0.78,
                                     "Shellcode / exploit pattern detected in payload",
                                     ["T1203", "T1068"]))
                break  # one alert per event

        # Unusual content-type / encoding anomaly
        ct = str(raw.get("content_type", ""))
        if ct and any(s in ct for s in ("application/x-www", "text/plain")) and \
                len(raw.get("payload", "")) > 5000:
            alerts.append(_alert(event, ThreatCategory.ZERO_DAY,
                                 Severity.MEDIUM, 0.62,
                                 f"Anomalous large payload with content-type: {ct}",
                                 ["T1190"]))

        return alerts
