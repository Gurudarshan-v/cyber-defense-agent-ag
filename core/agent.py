"""
Autonomous Cyber Defense Agent — Core Orchestrator
Observe → Detect → Analyze → Respond → Learn
"""

import asyncio
import logging
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

logger = logging.getLogger("CDA.Agent")


# ──────────────────────────────────────────────────────────────
# Enums & Data Models
# ──────────────────────────────────────────────────────────────

class Severity(Enum):
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4


class ThreatCategory(Enum):
    BRUTE_FORCE           = "brute_force"
    PORT_SCAN             = "port_scan"
    SQL_INJECTION         = "sql_injection"
    XSS                   = "xss"
    COMMAND_INJECTION     = "command_injection"
    PATH_TRAVERSAL        = "path_traversal"
    DATA_EXFILTRATION     = "data_exfiltration"
    MALWARE               = "malware"
    RANSOMWARE            = "ransomware"
    LATERAL_MOVEMENT      = "lateral_movement"
    PRIVILEGE_ESCALATION  = "privilege_escalation"
    DOS                   = "dos"
    INSIDER_THREAT        = "insider_threat"
    PHISHING              = "phishing"
    ZERO_DAY              = "zero_day"
    UNKNOWN               = "unknown"


class EventSource(Enum):
    NETWORK   = "network"
    SYSLOG    = "syslog"
    EDR       = "edr"
    INTEL     = "threat_intel"
    WAF       = "waf"
    IDS       = "ids"
    CLOUD     = "cloud"


@dataclass
class Event:
    source_ip:   str
    dest_ip:     str
    timestamp:   datetime
    event_type:  str
    raw_data:    dict
    source:      str = "unknown"
    enriched:    dict = field(default_factory=dict)
    id:          str = field(default_factory=lambda: str(uuid.uuid4())[:8])


@dataclass
class ThreatAlert:
    alert_id:    str
    event:       Event
    category:    ThreatCategory
    severity:    Severity
    confidence:  float
    description: str
    mitre_ttps:  list[str]  = field(default_factory=list)
    created_at:  datetime   = field(default_factory=datetime.now)
    resolved:    bool       = False
    false_positive: bool    = False
    notes:       str        = ""


@dataclass
class ResponseAction:
    action_type:  str
    target:       str
    reason:       str
    alert_id:     str
    auto_execute: bool     = False
    executed:     bool     = False
    result:       str      = ""
    timestamp:    datetime = field(default_factory=datetime.now)


# ──────────────────────────────────────────────────────────────
# Agent
# ──────────────────────────────────────────────────────────────

class CyberDefenseAgent:
    def __init__(self, config: dict | None = None):
        self.config  = config or {}
        self.running = False

        self._collectors: list = []
        self._detectors:  list = []
        self._responders: list = []

        self.event_queue:    asyncio.Queue = asyncio.Queue(maxsize=50_000)
        self.alert_history:  deque         = deque(maxlen=5_000)
        self.action_log:     list          = []
        self.blocked_ips:    set           = set()
        self.isolated_hosts: set           = set()

        self.stats = {
            "events_processed":  0,
            "alerts_raised":     0,
            "actions_taken":     0,
            "false_positives":   0,
            "threats_blocked":   0,
            "hosts_isolated":    0,
            "start_time":        None,
        }

        self.auto_threshold = Severity[self.config.get("auto_threshold", "CRITICAL")]
        logger.info("CyberDefenseAgent initialized | threshold=%s", self.auto_threshold.name)

    # ── Registration ──────────────────────────────────────────

    def register_collector(self, c): self._collectors.append(c)
    def register_detector(self, d):  self._detectors.append(d)
    def register_responder(self, r): self._responders.append(r)

    # ── Lifecycle ─────────────────────────────────────────────

    async def start(self):
        self.running = True
        self.stats["start_time"] = datetime.now()
        logger.info("Agent started")
        await asyncio.gather(
            self._collection_loop(),
            self._detection_loop(),
            self._learning_loop(),
        )

    async def stop(self):
        self.running = False

    # ── Collection ────────────────────────────────────────────

    async def _collection_loop(self):
        while self.running:
            for col in self._collectors:
                try:
                    events = await col.collect()
                    for ev in events:
                        await self.event_queue.put(ev)
                except Exception as exc:
                    logger.error("Collector error: %s", exc)
            await asyncio.sleep(self.config.get("collect_interval", 1))

    # ── Detection ─────────────────────────────────────────────

    async def _detection_loop(self):
        while self.running:
            try:
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                self.stats["events_processed"] += 1
                await self._process_event(event)
            except asyncio.TimeoutError:
                continue
            except Exception as exc:
                logger.error("Detection loop error: %s", exc)

    async def _process_event(self, event: Event):
        event = await self._enrich(event)
        alerts: list[ThreatAlert] = []
        for det in self._detectors:
            try:
                found = await det.analyze(event)
                alerts.extend(found)
            except Exception as exc:
                logger.error("Detector error: %s", exc)
        for alert in alerts:
            self.stats["alerts_raised"] += 1
            self.alert_history.append(alert)
            logger.warning("[%s] %s | %s | conf=%.0f%%",
                           alert.severity.name, alert.category.value,
                           alert.description, alert.confidence * 100)
            await self._plan_and_respond(alert)

    async def _enrich(self, event: Event) -> Event:
        event.enriched["processed_at"] = datetime.now().isoformat()
        return event

    # ── Response ──────────────────────────────────────────────

    async def _plan_and_respond(self, alert: ThreatAlert):
        actions = self._plan_actions(alert)
        for action in actions:
            should_auto = (
                alert.severity.value >= self.auto_threshold.value
                and action.auto_execute
            )
            if should_auto:
                await self._execute_action(action, alert)
            else:
                action.result = "queued_for_analyst"
            self.action_log.append(action)

    def _plan_actions(self, alert: ThreatAlert) -> list[ResponseAction]:
        actions = []
        aid = alert.alert_id
        src = alert.event.source_ip
        dst = alert.event.dest_ip

        cat = alert.category
        sev = alert.severity

        if cat == ThreatCategory.BRUTE_FORCE:
            actions.append(ResponseAction("block_ip", src, "Brute-force detected", aid,
                                          auto_execute=sev.value >= Severity.HIGH.value))

        elif cat == ThreatCategory.PORT_SCAN:
            actions.append(ResponseAction("rate_limit_ip", src, "Port scan", aid,
                                          auto_execute=sev == Severity.CRITICAL))

        elif cat in (ThreatCategory.MALWARE, ThreatCategory.RANSOMWARE):
            actions.append(ResponseAction("isolate_host", dst, f"{cat.value} detected", aid,
                                          auto_execute=True))
            actions.append(ResponseAction("block_ip", src, "Malware source", aid,
                                          auto_execute=True))

        elif cat in (ThreatCategory.LATERAL_MOVEMENT, ThreatCategory.PRIVILEGE_ESCALATION):
            actions.append(ResponseAction("isolate_host", dst, f"{cat.value}", aid,
                                          auto_execute=True))

        elif cat == ThreatCategory.DATA_EXFILTRATION:
            actions.append(ResponseAction("block_outbound", src, "Exfiltration attempt", aid,
                                          auto_execute=True))

        elif cat in (ThreatCategory.SQL_INJECTION, ThreatCategory.XSS,
                     ThreatCategory.COMMAND_INJECTION, ThreatCategory.PATH_TRAVERSAL):
            actions.append(ResponseAction("block_ip", src, f"Web attack: {cat.value}", aid,
                                          auto_execute=sev.value >= Severity.HIGH.value))
            actions.append(ResponseAction("patch_waf_rule", src, f"Add WAF rule for {cat.value}", aid,
                                          auto_execute=True))

        elif cat == ThreatCategory.DOS:
            actions.append(ResponseAction("rate_limit_ip", src, "DoS mitigation", aid,
                                          auto_execute=True))
            actions.append(ResponseAction("block_ip", src, "DoS source", aid,
                                          auto_execute=sev == Severity.CRITICAL))

        elif cat == ThreatCategory.INSIDER_THREAT:
            actions.append(ResponseAction("flag_account", src, "Insider threat indicators", aid,
                                          auto_execute=False))

        else:
            actions.append(ResponseAction("log_and_monitor", src, f"Unknown threat: {cat.value}", aid,
                                          auto_execute=False))

        if sev == Severity.CRITICAL:
            actions.append(ResponseAction("escalate", "soc_team", "CRITICAL — human review", aid,
                                          auto_execute=True))

        return actions

    async def _execute_action(self, action: ResponseAction, alert: ThreatAlert):
        self.stats["actions_taken"] += 1
        for resp in self._responders:
            if await resp.can_handle(action):
                result = await resp.execute(action, alert)
                action.executed = True
                action.result   = result
                if action.action_type == "block_ip":
                    self.blocked_ips.add(action.target)
                    self.stats["threats_blocked"] += 1
                if action.action_type == "isolate_host":
                    self.isolated_hosts.add(action.target)
                    self.stats["hosts_isolated"] += 1
                return
        action.result = "no_responder"

    # ── Learning ──────────────────────────────────────────────

    async def _learning_loop(self):
        while self.running:
            await asyncio.sleep(self.config.get("learn_interval", 60))
            self._tune_thresholds()

    def _tune_thresholds(self):
        resolved = [a for a in self.alert_history if a.resolved]
        fps = [a for a in resolved if a.false_positive]
        if fps:
            self.stats["false_positives"] = len(fps)
        logger.debug("Learning loop | false_positives=%d", len(fps))

    # ── Public API ────────────────────────────────────────────

    def summary(self) -> dict:
        uptime = (
            (datetime.now() - self.stats["start_time"]).total_seconds()
            if self.stats["start_time"] else 0
        )
        return {**self.stats, "uptime_seconds": round(uptime),
                "recent_alerts": len(self.alert_history),
                "blocked_ips":   len(self.blocked_ips),
                "isolated_hosts": len(self.isolated_hosts),
                "pending_actions": sum(1 for a in self.action_log if not a.executed)}

    def get_alerts(self, limit=100, severity=None, category=None, resolved=None) -> list:
        alerts = list(self.alert_history)
        if severity:
            alerts = [a for a in alerts if a.severity.name == severity.upper()]
        if category:
            alerts = [a for a in alerts if a.category.value == category]
        if resolved is not None:
            alerts = [a for a in alerts if a.resolved == resolved]
        return list(reversed(alerts[-limit:]))

    def resolve_alert(self, alert_id: str, false_positive: bool = False, notes: str = "") -> bool:
        for a in self.alert_history:
            if a.alert_id == alert_id:
                a.resolved       = True
                a.false_positive = false_positive
                a.notes          = notes
                if false_positive:
                    self.stats["false_positives"] += 1
                return True
        return False
