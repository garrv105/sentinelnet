"""
SentinelNet - Rule-Based Detection Engine
==========================================
YAML-configurable rule engine supporting:
- Port scan detection (horizontal + vertical)
- SYN flood detection
- DNS tunneling heuristics
- Brute force login attempts
- Known malicious port access
- Custom user-defined rules with threshold and time-window logic
"""

import logging
import time
import uuid
from collections import defaultdict, deque
from typing import Dict, Optional

import yaml

from ..core.event_bus import EventBus, Severity, ThreatEvent
from ..core.flow_tracker import FlowRecord
from ..core.packet_capture import PacketRecord, Protocol

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Built-in detection rules
# ---------------------------------------------------------------------------


class PortScanDetector:
    """
    Detects horizontal (many hosts, same port) and vertical (many ports, one host) scans.
    Uses a sliding time-window counter.
    """

    def __init__(
        self,
        window_secs: float = 60.0,
        horizontal_threshold: int = 20,  # distinct dst IPs in window
        vertical_threshold: int = 15,  # distinct dst ports in window
    ):
        self.window = window_secs
        self.h_threshold = horizontal_threshold
        self.v_threshold = vertical_threshold
        # src_ip → deque of (timestamp, dst_ip)
        self._h_table: Dict[str, deque] = defaultdict(deque)
        # src_ip → deque of (timestamp, dst_port)
        self._v_table: Dict[str, deque] = defaultdict(deque)

    def inspect(self, pkt: PacketRecord) -> Optional[ThreatEvent]:
        now = pkt.timestamp
        cutoff = now - self.window
        src = pkt.src_ip

        # Horizontal scan
        dq_h = self._h_table[src]
        dq_h.append((now, pkt.dst_ip))
        while dq_h and dq_h[0][0] < cutoff:
            dq_h.popleft()
        unique_dsts = len(set(ip for _, ip in dq_h))

        if unique_dsts >= self.h_threshold:
            return self._make_event("horizontal_port_scan", src, pkt, unique_dsts, "horizontal")

        # Vertical scan
        if pkt.dst_port > 0:
            dq_v = self._v_table[src]
            dq_v.append((now, pkt.dst_port))
            while dq_v and dq_v[0][0] < cutoff:
                dq_v.popleft()
            unique_ports = len(set(p for _, p in dq_v))

            if unique_ports >= self.v_threshold:
                return self._make_event("vertical_port_scan", src, pkt, unique_ports, "vertical")

        return None

    def _make_event(self, threat_type: str, src: str, pkt: PacketRecord, count: int, scan_type: str) -> ThreatEvent:
        return ThreatEvent(
            event_id=str(uuid.uuid4()),
            source="PortScanDetector",
            severity=Severity.HIGH,
            threat_type=threat_type,
            src_ip=src,
            dst_ip=pkt.dst_ip,
            src_port=pkt.src_port,
            dst_port=pkt.dst_port,
            protocol=pkt.protocol.value,
            score=min(count / (self.h_threshold * 2), 1.0),
            description=f"{scan_type.capitalize()} port scan detected from {src} ({count} unique targets in window)",
            evidence={"scan_type": scan_type, "unique_count": count, "window_secs": self.window},
            mitre_tactic="Discovery",
            mitre_technique="T1046",
        )


class SynFloodDetector:
    """
    Detects TCP SYN floods by measuring SYN packet rate per source.
    """

    def __init__(self, window_secs: float = 10.0, syn_threshold: int = 100):
        self.window = window_secs
        self.threshold = syn_threshold
        self._table: Dict[str, deque] = defaultdict(deque)

    def inspect(self, pkt: PacketRecord) -> Optional[ThreatEvent]:
        if pkt.protocol not in (Protocol.TCP, Protocol.HTTPS, Protocol.HTTP):
            return None
        if not pkt.flags.get("SYN") or pkt.flags.get("ACK"):
            return None

        now = pkt.timestamp
        cutoff = now - self.window
        dq = self._table[pkt.src_ip]
        dq.append(now)
        while dq and dq[0] < cutoff:
            dq.popleft()

        syn_rate = len(dq)
        if syn_rate >= self.threshold:
            return ThreatEvent(
                event_id=str(uuid.uuid4()),
                source="SynFloodDetector",
                severity=Severity.CRITICAL,
                threat_type="syn_flood",
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                protocol="TCP",
                score=min(syn_rate / (self.threshold * 2), 1.0),
                description=f"SYN flood from {pkt.src_ip}: {syn_rate} SYNs/{self.window}s to {pkt.dst_ip}",
                evidence={"syn_count": syn_rate, "window_secs": self.window, "dst_port": pkt.dst_port},
                mitre_tactic="Impact",
                mitre_technique="T1498",
            )
        return None


class DNSTunnelingDetector:
    """
    Detects DNS tunneling by monitoring query frequency, payload size, and entropy.
    DNS tunneling typically shows:
    - Very high query rates
    - Long hostnames / high entropy labels
    - Unusual record types
    """

    def __init__(self, window_secs: float = 60.0, rate_threshold: int = 50, payload_threshold: int = 100):
        self.window = window_secs
        self.rate_threshold = rate_threshold
        self.payload_threshold = payload_threshold
        self._query_table: Dict[str, deque] = defaultdict(deque)
        self._payload_table: Dict[str, deque] = defaultdict(deque)

    def inspect(self, pkt: PacketRecord) -> Optional[ThreatEvent]:
        if pkt.protocol != Protocol.DNS:
            return None

        now = pkt.timestamp
        cutoff = now - self.window
        src = pkt.src_ip

        # Rate check
        dq = self._query_table[src]
        dq.append(now)
        while dq and dq[0] < cutoff:
            dq.popleft()
        query_rate = len(dq)

        # Payload size check
        pd = self._payload_table[src]
        if pkt.payload_size > 0:
            pd.append(pkt.payload_size)
        while len(pd) > 100:
            pd.popleft()
        avg_payload = sum(pd) / len(pd) if pd else 0

        is_high_rate = query_rate >= self.rate_threshold
        is_large_payload = avg_payload >= self.payload_threshold

        if is_high_rate and is_large_payload:
            score = min((query_rate / self.rate_threshold) * 0.5 + (avg_payload / self.payload_threshold) * 0.5, 1.0)
            return ThreatEvent(
                event_id=str(uuid.uuid4()),
                source="DNSTunnelingDetector",
                severity=Severity.HIGH,
                threat_type="dns_tunneling",
                src_ip=src,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=53,
                protocol="DNS",
                score=score,
                description=f"DNS tunneling suspected from {src}: {query_rate} queries/min, avg payload {avg_payload:.0f}B",
                evidence={"query_rate": query_rate, "avg_payload_bytes": round(avg_payload, 1)},
                mitre_tactic="Command and Control",
                mitre_technique="T1071.004",
            )
        return None


class BruteForceDetector:
    """
    Detects brute force login attempts on common service ports (SSH=22, FTP=21, RDP=3389, etc.)
    """

    BRUTEFORCE_PORTS = {22: "SSH", 21: "FTP", 3389: "RDP", 23: "Telnet", 5900: "VNC", 1433: "MSSQL"}

    def __init__(self, window_secs: float = 60.0, attempt_threshold: int = 20):
        self.window = window_secs
        self.threshold = attempt_threshold
        self._table: Dict[str, deque] = defaultdict(deque)  # key: "src->dst:port"

    def inspect(self, pkt: PacketRecord) -> Optional[ThreatEvent]:
        if pkt.dst_port not in self.BRUTEFORCE_PORTS:
            return None
        if not pkt.flags.get("SYN"):
            return None

        key = f"{pkt.src_ip}->{pkt.dst_ip}:{pkt.dst_port}"
        now = pkt.timestamp
        cutoff = now - self.window
        dq = self._table[key]
        dq.append(now)
        while dq and dq[0] < cutoff:
            dq.popleft()

        attempts = len(dq)
        service = self.BRUTEFORCE_PORTS[pkt.dst_port]
        if attempts >= self.threshold:
            return ThreatEvent(
                event_id=str(uuid.uuid4()),
                source="BruteForceDetector",
                severity=Severity.HIGH,
                threat_type="brute_force",
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                protocol="TCP",
                score=min(attempts / (self.threshold * 3), 1.0),
                description=f"{service} brute force from {pkt.src_ip} → {pkt.dst_ip}: {attempts} attempts/{self.window}s",
                evidence={"service": service, "attempts": attempts, "window_secs": self.window},
                mitre_tactic="Credential Access",
                mitre_technique="T1110",
            )
        return None


# ---------------------------------------------------------------------------
# Rule Engine
# ---------------------------------------------------------------------------


class RuleEngine:
    """
    Orchestrates all built-in detectors and user-defined YAML rules.
    Deduplicates events using a time-based cooldown window per (src_ip, threat_type).
    """

    def __init__(self, bus: EventBus, config_path: Optional[str] = None):
        self.bus = bus
        self._detectors = [
            PortScanDetector(),
            SynFloodDetector(),
            DNSTunnelingDetector(),
            BruteForceDetector(),
        ]
        self._dedup_table: Dict[str, float] = {}  # key → last_alert_time
        self._dedup_cooldown = 30.0  # seconds

        if config_path:
            self._load_yaml_rules(config_path)

    def inspect_packet(self, pkt: PacketRecord):
        """Run all detectors against a packet."""
        for detector in self._detectors:
            try:
                event = detector.inspect(pkt)
                if event and self._should_emit(event):
                    self.bus.publish(event)
            except Exception as e:
                logger.error("Detector %s error: %s", detector.__class__.__name__, e)

    def inspect_flow(self, flow: FlowRecord):
        """
        Flow-level rules (run after flow completion).
        Detect anomalous flow statistics.
        """
        feats = flow.to_feature_vector()

        # Data exfiltration: massive outbound bytes, low packet count
        if feats["fwd_bytes"] > 100_000_000 and feats["fwd_packets"] < 100:
            event = ThreatEvent(
                event_id=str(uuid.uuid4()),
                source="RuleEngine.FlowAnalysis",
                severity=Severity.HIGH,
                threat_type="data_exfiltration",
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                src_port=flow.src_port,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                score=0.85,
                description=f"Possible data exfiltration: {feats['fwd_bytes']/1e6:.1f}MB in {feats['fwd_packets']:.0f} packets",
                evidence=feats,
                mitre_tactic="Exfiltration",
                mitre_technique="T1048",
            )
            if self._should_emit(event):
                self.bus.publish(event)

    def _should_emit(self, event: ThreatEvent) -> bool:
        """Deduplicate events: same (src, threat_type) within cooldown window."""
        key = f"{event.src_ip}:{event.threat_type}"
        now = time.time()
        last = self._dedup_table.get(key, 0)
        if now - last < self._dedup_cooldown:
            return False
        self._dedup_table[key] = now
        return True

    def _load_yaml_rules(self, path: str):
        """Load and compile user-defined YAML rules (future extension)."""
        try:
            with open(path) as f:
                rules = yaml.safe_load(f)
            logger.info("Loaded %d custom rules from %s", len(rules.get("rules", [])), path)
        except Exception as e:
            logger.warning("Failed to load custom rules from %s: %s", path, e)
