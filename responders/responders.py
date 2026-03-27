"""
Response Executors
FirewallResponder, HostIsolationResponder, WAFResponder,
ProcessKillResponder, AccountResponder, EscalationResponder
"""

import logging
import subprocess
from core.agent import ResponseAction, ThreatAlert

logger = logging.getLogger("CDA.Responders")


class BaseResponder:
    async def can_handle(self, action: ResponseAction) -> bool:
        raise NotImplementedError
    async def execute(self, action: ResponseAction, alert: ThreatAlert) -> str:
        raise NotImplementedError


# ──────────────────────────────────────────────────────────────
# Firewall Responder
# ──────────────────────────────────────────────────────────────

class FirewallResponder(BaseResponder):
    HANDLES = {"block_ip", "block_outbound", "rate_limit_ip"}

    def __init__(self, dry_run: bool = True):
        self.dry_run    = dry_run
        self.blocked:   set[str] = set()
        self.rate_limited: set[str] = set()

    async def can_handle(self, action: ResponseAction) -> bool:
        return action.action_type in self.HANDLES

    async def execute(self, action: ResponseAction, alert: ThreatAlert) -> str:
        ip = action.target
        if action.action_type == "block_ip":
            cmd = f"iptables -I INPUT -s {ip} -j DROP"
        elif action.action_type == "block_outbound":
            cmd = f"iptables -I OUTPUT -d {ip} -j DROP"
        else:
            cmd = (f"iptables -I INPUT -s {ip} "
                   "-m limit --limit 20/min --limit-burst 50 -j ACCEPT && "
                   f"iptables -A INPUT -s {ip} -j DROP")

        if self.dry_run:
            logger.info("[DRY-RUN] FW: %s", cmd)
            self.blocked.add(ip)
            return f"dry_run:{cmd}"

        try:
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
            self.blocked.add(ip)
            return f"executed:{cmd}"
        except subprocess.CalledProcessError as e:
            return f"error:{e.stderr.decode()}"


# ──────────────────────────────────────────────────────────────
# Host Isolation Responder
# ──────────────────────────────────────────────────────────────

class HostIsolationResponder(BaseResponder):
    def __init__(self, dry_run: bool = True, edr_client=None):
        self.dry_run    = dry_run
        self.edr_client = edr_client
        self.isolated:  set[str] = set()

    async def can_handle(self, action: ResponseAction) -> bool:
        return action.action_type == "isolate_host"

    async def execute(self, action: ResponseAction, alert: ThreatAlert) -> str:
        host = action.target
        if host in self.isolated:
            return f"already_isolated:{host}"

        if self.edr_client:
            try:
                await self.edr_client.isolate(host)
                self.isolated.add(host)
                return f"edr_isolated:{host}"
            except Exception as e:
                return f"edr_error:{e}"

        if self.dry_run:
            logger.info("[DRY-RUN] ISOLATE: %s", host)
            self.isolated.add(host)
            return f"dry_run_isolated:{host}"

        cmds = [f"iptables -I INPUT -s {host} -j DROP",
                f"iptables -I OUTPUT -d {host} -j DROP"]
        for c in cmds:
            subprocess.run(c, shell=True, check=True)
        self.isolated.add(host)
        return f"isolated:{host}"


# ──────────────────────────────────────────────────────────────
# WAF Rule Responder
# ──────────────────────────────────────────────────────────────

class WAFResponder(BaseResponder):
    """Add dynamic block rules to nginx / modsecurity / custom WAF."""

    def __init__(self, waf_config_path: str = "/etc/nginx/blocked_ips.conf",
                 dry_run: bool = True):
        self.path    = waf_config_path
        self.dry_run = dry_run
        self.rules:  list[str] = []

    async def can_handle(self, action: ResponseAction) -> bool:
        return action.action_type == "patch_waf_rule"

    async def execute(self, action: ResponseAction, alert: ThreatAlert) -> str:
        rule = f"deny {action.target};"
        self.rules.append(rule)
        if self.dry_run:
            logger.info("[DRY-RUN] WAF rule: %s", rule)
            return f"dry_run_waf:{rule}"
        try:
            with open(self.path, "a") as f:
                f.write(rule + "\n")
            subprocess.run(["nginx", "-s", "reload"], check=True)
            return f"waf_rule_added:{rule}"
        except Exception as e:
            return f"waf_error:{e}"


# ──────────────────────────────────────────────────────────────
# Process Kill Responder
# ──────────────────────────────────────────────────────────────

class ProcessKillResponder(BaseResponder):
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run

    async def can_handle(self, action: ResponseAction) -> bool:
        return action.action_type == "kill_process"

    async def execute(self, action: ResponseAction, alert: ThreatAlert) -> str:
        pid = action.target
        if self.dry_run:
            logger.info("[DRY-RUN] KILL PID %s", pid)
            return f"dry_run_killed:{pid}"
        try:
            subprocess.run(["kill", "-9", str(pid)], check=True)
            return f"killed:{pid}"
        except Exception as e:
            return f"kill_failed:{e}"


# ──────────────────────────────────────────────────────────────
# Account Responder
# ──────────────────────────────────────────────────────────────

class AccountResponder(BaseResponder):
    """Disable/flag user accounts on insider threat detection."""

    def __init__(self, dry_run: bool = True):
        self.dry_run    = dry_run
        self.flagged:   set[str] = set()
        self.disabled:  set[str] = set()

    async def can_handle(self, action: ResponseAction) -> bool:
        return action.action_type in {"flag_account", "disable_account"}

    async def execute(self, action: ResponseAction, alert: ThreatAlert) -> str:
        user = action.target
        if action.action_type == "flag_account":
            self.flagged.add(user)
            logger.info("[DRY-RUN] FLAG account: %s", user)
            return f"flagged:{user}"
        if self.dry_run:
            logger.info("[DRY-RUN] DISABLE account: %s", user)
            self.disabled.add(user)
            return f"dry_run_disabled:{user}"
        try:
            subprocess.run(["usermod", "-L", user], check=True)
            self.disabled.add(user)
            return f"disabled:{user}"
        except Exception as e:
            return f"disable_error:{e}"


# ──────────────────────────────────────────────────────────────
# Generic Logging Responder
# ──────────────────────────────────────────────────────────────

class LoggingResponder(BaseResponder):
    """Catch-all — logs anything that other responders don't handle."""

    HANDLES = {"log_and_monitor", "escalate"}

    async def can_handle(self, action: ResponseAction) -> bool:
        return action.action_type in self.HANDLES

    async def execute(self, action: ResponseAction, alert: ThreatAlert) -> str:
        if action.action_type == "escalate":
            logger.critical(
                "🚨 ESCALATE [%s] %s | %s | src=%s | TTPs=%s",
                alert.severity.name, alert.category.value,
                alert.description, alert.event.source_ip,
                ",".join(alert.mitre_ttps)
            )
            return "escalated_to_soc"
        logger.info("MONITOR: %s → %s", action.action_type, action.target)
        return "logged"


# ──────────────────────────────────────────────────────────────
# Webhook / Escalation Responder
# ──────────────────────────────────────────────────────────────

class EscalationResponder(BaseResponder):
    def __init__(self, webhook_url: str = "", channel: str = "#soc-alerts"):
        self.webhook_url  = webhook_url
        self.channel      = channel
        self.escalations: list[dict] = []

    async def can_handle(self, action: ResponseAction) -> bool:
        return action.action_type == "escalate"

    async def execute(self, action: ResponseAction, alert: ThreatAlert) -> str:
        payload = {
            "channel": self.channel,
            "text": (
                f"🚨 *CRITICAL [{alert.alert_id}]*\n"
                f"• Category: {alert.category.value}\n"
                f"• Severity: {alert.severity.name}\n"
                f"• Source IP: {alert.event.source_ip}\n"
                f"• Dest IP: {alert.event.dest_ip}\n"
                f"• TTPs: {', '.join(alert.mitre_ttps) or 'N/A'}\n"
                f"• Details: {alert.description}"
            )
        }
        self.escalations.append(payload)
        if not self.webhook_url:
            logger.warning("ESCALATION: %s", payload["text"])
            return "escalated_local"
        try:
            import urllib.request, json
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                return f"webhook_{r.status}"
        except Exception as e:
            return f"webhook_error:{e}"
