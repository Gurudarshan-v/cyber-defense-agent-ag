"""
Autonomous Cyber Defense Agent — CLI Entry Point

Usage:
  python main.py               # terminal mode (simulation)
  python web_server.py         # web dashboard at localhost:8000
"""

import asyncio, argparse, logging, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

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

async def main(args):
    agent = CyberDefenseAgent(config={"auto_threshold": args.threshold})
    for col in [NetworkCollector(simulate=not args.live, attack_rate=0.4),
                SyslogCollector(simulate=not args.live),
                EDRCollector(simulate=not args.live),
                ThreatIntelCollector(simulate=not args.live),
                WAFCollector(simulate=not args.live),
                CloudCollector(simulate=not args.live)]:
        agent.register_collector(col)
    for det in [SignatureDetector(), AnomalyDetector(), MLThreatDetector(),
                BehavioralDetector(), NetworkFlowDetector(),
                InsiderThreatDetector(), ZeroDayDetector()]:
        agent.register_detector(det)
    for resp in [FirewallResponder(dry_run=not args.execute),
                 HostIsolationResponder(dry_run=not args.execute),
                 WAFResponder(dry_run=not args.execute),
                 ProcessKillResponder(dry_run=not args.execute),
                 AccountResponder(dry_run=not args.execute),
                 EscalationResponder(webhook_url=args.webhook or ""),
                 LoggingResponder()]:
        agent.register_responder(resp)
    try:
        await agent.start()
    except KeyboardInterrupt:
        await agent.stop()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--live",      action="store_true")
    p.add_argument("--execute",   action="store_true")
    p.add_argument("--threshold", default="HIGH",
                   choices=["LOW","MEDIUM","HIGH","CRITICAL"])
    p.add_argument("--webhook",   default="")
    asyncio.run(main(p.parse_args()))
