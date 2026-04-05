"""
SentinelNet - Automated Response Manager
==========================================
Pluggable response framework with:
- IP blocking via iptables / firewall rules
- Alerting (Slack webhook, email, syslog)
- Structured incident logging (JSON/SQLite)
- Rate limiting to prevent response storms
- Severity-gated response policies
"""

import json
import logging
import os
import subprocess
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set
from pathlib import Path

import requests

from ..core.event_bus import ThreatEvent, Severity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Base responder interface
# ---------------------------------------------------------------------------

class BaseResponder(ABC):
    """Abstract base class for all response modules."""

    name: str = "BaseResponder"
    min_severity: Severity = Severity.LOW

    @abstractmethod
    def respond(self, event: ThreatEvent):
        """Execute the response action for the given event."""
        ...

    def can_respond(self, event: ThreatEvent) -> bool:
        return event.severity >= self.min_severity


# ---------------------------------------------------------------------------
# Concrete responders
# ---------------------------------------------------------------------------

class IPBlocker(BaseResponder):
    """
    Blocks malicious source IPs using iptables (Linux) or ipfw (macOS).
    Maintains a blocklist with configurable TTL and a whitelist of protected IPs.
    Requires root/admin privileges.
    """

    name = "IPBlocker"
    min_severity = Severity.HIGH

    def __init__(
        self,
        whitelist: Optional[List[str]] = None,
        block_duration_secs: int = 3600,
        dry_run: bool = False,
    ):
        self.whitelist: Set[str] = set(whitelist or [])
        self.block_duration = block_duration_secs
        self.dry_run = dry_run
        self._blocked: Dict[str, float] = {}  # ip → unblock_time
        self._lock = threading.Lock()

        # Start TTL cleanup thread
        t = threading.Thread(target=self._ttl_cleanup, daemon=True, name="ipblocker-ttl")
        t.start()

    def respond(self, event: ThreatEvent):
        ip = event.src_ip
        if ip in self.whitelist:
            logger.info("IPBlocker: %s is whitelisted, skipping block", ip)
            return

        with self._lock:
            if ip in self._blocked:
                logger.debug("IPBlocker: %s already blocked", ip)
                return
            self._blocked[ip] = time.time() + self.block_duration

        self._apply_block(ip)
        logger.warning("BLOCKED: %s (reason=%s, ttl=%ds)", ip, event.threat_type, self.block_duration)

    def unblock(self, ip: str):
        with self._lock:
            if ip in self._blocked:
                del self._blocked[ip]
        self._remove_block(ip)
        logger.info("UNBLOCKED: %s", ip)

    def get_blocklist(self) -> List[Dict]:
        with self._lock:
            now = time.time()
            return [
                {"ip": ip, "expires_in_secs": max(0, int(t - now))}
                for ip, t in self._blocked.items()
            ]

    def _apply_block(self, ip: str):
        if self.dry_run:
            logger.info("[DRY RUN] Would block IP: %s", ip)
            return
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, check=True, timeout=5
            )
        except FileNotFoundError:
            logger.warning("iptables not available. IP %s NOT blocked in firewall.", ip)
        except subprocess.CalledProcessError as e:
            logger.error("iptables error for %s: %s", ip, e.stderr)

    def _remove_block(self, ip: str):
        if self.dry_run:
            return
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass

    def _ttl_cleanup(self):
        while True:
            time.sleep(60)
            now = time.time()
            with self._lock:
                expired = [ip for ip, t in self._blocked.items() if t <= now]
            for ip in expired:
                self.unblock(ip)


class IncidentLogger(BaseResponder):
    """
    Persists all threat events to:
    - Structured JSON log file (NDJSON format)
    - SQLite database for querying
    """

    name = "IncidentLogger"
    min_severity = Severity.INFO

    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._json_path = self.log_dir / "incidents.ndjson"
        self._db_path = self.log_dir / "incidents.db"
        self._lock = threading.Lock()
        self._init_db()

    def respond(self, event: ThreatEvent):
        with self._lock:
            self._write_json(event)
            self._write_db(event)

    def query(
        self,
        severity: Optional[str] = None,
        threat_type: Optional[str] = None,
        src_ip: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict]:
        """Query the incident database."""
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            where = []
            params = []
            if severity:
                where.append("severity = ?")
                params.append(severity)
            if threat_type:
                where.append("threat_type = ?")
                params.append(threat_type)
            if src_ip:
                where.append("src_ip = ?")
                params.append(src_ip)
            sql = "SELECT * FROM incidents"
            if where:
                sql += " WHERE " + " AND ".join(where)
            sql += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            return [dict(row) for row in conn.execute(sql, params).fetchall()]

    def _write_json(self, event: ThreatEvent):
        with open(self._json_path, "a") as f:
            f.write(json.dumps(event.to_dict()) + "\n")

    def _init_db(self):
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    event_id TEXT PRIMARY KEY,
                    timestamp REAL,
                    source TEXT,
                    severity TEXT,
                    threat_type TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    score REAL,
                    description TEXT,
                    evidence TEXT,
                    mitre_tactic TEXT,
                    mitre_technique TEXT
                )
            """)

    def _write_db(self, event: ThreatEvent):
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("""
                INSERT OR IGNORE INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                event.event_id,
                event.timestamp,
                event.source,
                event.severity.label(),
                event.threat_type,
                event.src_ip,
                event.dst_ip,
                event.src_port,
                event.dst_port,
                event.protocol,
                event.score,
                event.description,
                json.dumps(event.evidence),
                event.mitre_tactic,
                event.mitre_technique,
            ))


class SlackAlerter(BaseResponder):
    """
    Sends structured Slack alerts via webhook for high/critical threats.
    """

    name = "SlackAlerter"
    min_severity = Severity.HIGH

    SEVERITY_COLORS = {
        Severity.INFO: "#36a64f",
        Severity.LOW: "#ffcc00",
        Severity.MEDIUM: "#ff9900",
        Severity.HIGH: "#ff4500",
        Severity.CRITICAL: "#cc0000",
    }

    def __init__(self, webhook_url: str, rate_limit_secs: float = 60.0):
        self.webhook_url = webhook_url
        self.rate_limit = rate_limit_secs
        self._last_sent: Dict[str, float] = defaultdict(float)
        self._lock = threading.Lock()

    def respond(self, event: ThreatEvent):
        key = f"{event.src_ip}:{event.threat_type}"
        with self._lock:
            if time.time() - self._last_sent[key] < self.rate_limit:
                return
            self._last_sent[key] = time.time()

        payload = self._build_payload(event)
        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=5)
            resp.raise_for_status()
            logger.info("Slack alert sent for event %s", event.event_id)
        except Exception as e:
            logger.error("Slack alert failed: %s", e)

    def _build_payload(self, event: ThreatEvent) -> Dict:
        color = self.SEVERITY_COLORS.get(event.severity, "#888888")
        ts = datetime.utcfromtimestamp(event.timestamp).strftime("%Y-%m-%d %H:%M:%S UTC")
        return {
            "attachments": [{
                "color": color,
                "title": f"[{event.severity.label()}] {event.threat_type.replace('_', ' ').title()}",
                "text": event.description,
                "fields": [
                    {"title": "Source IP", "value": event.src_ip, "short": True},
                    {"title": "Destination", "value": f"{event.dst_ip}:{event.dst_port}", "short": True},
                    {"title": "Score", "value": f"{event.score:.3f}", "short": True},
                    {"title": "Protocol", "value": event.protocol, "short": True},
                    {"title": "MITRE", "value": f"{event.mitre_tactic} / {event.mitre_technique}", "short": True},
                    {"title": "Event ID", "value": event.event_id[:8], "short": True},
                ],
                "footer": f"SentinelNet | {ts}",
            }]
        }


# ---------------------------------------------------------------------------
# Response Manager
# ---------------------------------------------------------------------------

class ResponseManager:
    """
    Connects to the EventBus and dispatches events to registered responders
    based on severity policies.
    """

    def __init__(self, bus, config: Optional[Dict] = None):
        self.bus = bus
        self._responders: List[BaseResponder] = []
        config = config or {}

        # Always add incident logger
        self._responders.append(IncidentLogger(log_dir=config.get("log_dir", "logs")))

        # Optional IP blocker
        if config.get("enable_ip_blocker", False):
            self._responders.append(IPBlocker(
                whitelist=config.get("ip_whitelist", []),
                block_duration_secs=config.get("block_duration_secs", 3600),
                dry_run=config.get("dry_run", True),
            ))

        # Optional Slack alerter
        if config.get("slack_webhook"):
            self._responders.append(SlackAlerter(
                webhook_url=config["slack_webhook"],
                rate_limit_secs=config.get("slack_rate_limit_secs", 60),
            ))

        # Subscribe to all events
        bus.subscribe("*", self._handle_event)
        logger.info("ResponseManager initialized with %d responders", len(self._responders))

    def add_responder(self, responder: BaseResponder):
        self._responders.append(responder)

    def get_blocklist(self) -> List[Dict]:
        for r in self._responders:
            if isinstance(r, IPBlocker):
                return r.get_blocklist()
        return []

    def query_incidents(self, **kwargs) -> List[Dict]:
        for r in self._responders:
            if isinstance(r, IncidentLogger):
                return r.query(**kwargs)
        return []

    def _handle_event(self, event: ThreatEvent):
        for responder in self._responders:
            if responder.can_respond(event):
                try:
                    responder.respond(event)
                except Exception as e:
                    logger.error("Responder %s failed: %s", responder.name, e)
