"""
SentinelNet - Network Flow Tracker
====================================
Aggregates individual packets into bidirectional network flows.
Computes per-flow statistics used by anomaly detectors.
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .packet_capture import PacketRecord

logger = logging.getLogger(__name__)

FlowKey = Tuple[str, str, int, int, str]  # (src_ip, dst_ip, src_port, dst_port, proto)


@dataclass
class FlowRecord:
    """Bidirectional network flow with statistical features."""

    key: FlowKey
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    # Timing
    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    # Counters
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    # Inter-arrival times (ms)
    fwd_iat: List[float] = field(default_factory=list)
    bwd_iat: List[float] = field(default_factory=list)
    _last_fwd_ts: float = 0.0
    _last_bwd_ts: float = 0.0

    # TCP flag counts
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0

    # Payload
    fwd_payload: int = 0
    bwd_payload: int = 0

    @property
    def duration(self) -> float:
        return max(self.last_seen - self.start_time, 1e-6)

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def bytes_per_second(self) -> float:
        return self.total_bytes / self.duration

    @property
    def packets_per_second(self) -> float:
        return self.total_packets / self.duration

    @property
    def avg_fwd_iat(self) -> float:
        return sum(self.fwd_iat) / len(self.fwd_iat) if self.fwd_iat else 0.0

    @property
    def avg_bwd_iat(self) -> float:
        return sum(self.bwd_iat) / len(self.bwd_iat) if self.bwd_iat else 0.0

    @property
    def flag_ratio(self) -> float:
        """SYN-to-ACK ratio — useful for detecting SYN floods."""
        return self.syn_count / max(self.ack_count, 1)

    def to_feature_vector(self) -> Dict[str, float]:
        """Return numeric features for ML anomaly detectors."""
        return {
            "duration": self.duration,
            "fwd_packets": float(self.fwd_packets),
            "bwd_packets": float(self.bwd_packets),
            "fwd_bytes": float(self.fwd_bytes),
            "bwd_bytes": float(self.bwd_bytes),
            "bytes_per_sec": self.bytes_per_second,
            "packets_per_sec": self.packets_per_second,
            "avg_fwd_iat": self.avg_fwd_iat,
            "avg_bwd_iat": self.avg_bwd_iat,
            "syn_count": float(self.syn_count),
            "fin_count": float(self.fin_count),
            "rst_count": float(self.rst_count),
            "psh_count": float(self.psh_count),
            "flag_ratio": self.flag_ratio,
            "fwd_payload": float(self.fwd_payload),
            "bwd_payload": float(self.bwd_payload),
            "pkt_size_ratio": self.fwd_bytes / max(self.bwd_bytes, 1),
        }

    def to_dict(self) -> Dict:
        d = self.to_feature_vector()
        d.update(
            {
                "src_ip": self.src_ip,
                "dst_ip": self.dst_ip,
                "src_port": self.src_port,
                "dst_port": self.dst_port,
                "protocol": self.protocol,
                "start_time": self.start_time,
                "last_seen": self.last_seen,
            }
        )
        return d


class FlowTracker:
    """
    Stateful flow aggregator.

    Maintains a table of active flows keyed by (src, dst, sport, dport, proto).
    Expired flows (idle > timeout) are evicted and emitted for analysis.

    Thread-safe via RLock.
    """

    def __init__(
        self,
        flow_timeout: float = 120.0,  # seconds of inactivity before eviction
        max_flows: int = 100_000,
        eviction_interval: float = 30.0,
    ):
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows
        self.eviction_interval = eviction_interval

        self._flows: Dict[FlowKey, FlowRecord] = {}
        self._lock = threading.RLock()
        self._completed_flows: List[FlowRecord] = []

        self._eviction_thread = threading.Thread(target=self._eviction_loop, name="flow-eviction", daemon=True)
        self._eviction_thread.start()

    def update(self, pkt: PacketRecord) -> Optional[FlowRecord]:
        """
        Update flow table with a new packet.
        Returns the FlowRecord that was updated.
        """
        key = self._make_key(pkt)
        rev_key = self._make_reverse_key(pkt)

        with self._lock:
            # Enforce max flow table size
            if len(self._flows) >= self.max_flows and key not in self._flows:
                logger.warning("Flow table full (%d entries), dropping new flow", self.max_flows)
                return None

            # Determine direction
            is_forward = key in self._flows or rev_key not in self._flows

            if is_forward:
                flow = self._flows.setdefault(
                    key,
                    FlowRecord(
                        key=key,
                        src_ip=pkt.src_ip,
                        dst_ip=pkt.dst_ip,
                        src_port=pkt.src_port,
                        dst_port=pkt.dst_port,
                        protocol=pkt.protocol.value,
                        start_time=pkt.timestamp,
                        last_seen=pkt.timestamp,
                        _last_fwd_ts=pkt.timestamp,
                    ),
                )
                flow.fwd_packets += 1
                flow.fwd_bytes += pkt.length
                flow.fwd_payload += pkt.payload_size
                if flow._last_fwd_ts and flow._last_fwd_ts != pkt.timestamp:
                    flow.fwd_iat.append((pkt.timestamp - flow._last_fwd_ts) * 1000)
                flow._last_fwd_ts = pkt.timestamp
            else:
                flow = self._flows[rev_key]
                flow.bwd_packets += 1
                flow.bwd_bytes += pkt.length
                flow.bwd_payload += pkt.payload_size
                if flow._last_bwd_ts and flow._last_bwd_ts != pkt.timestamp:
                    flow.bwd_iat.append((pkt.timestamp - flow._last_bwd_ts) * 1000)
                flow._last_bwd_ts = pkt.timestamp

            # Update flags
            for flag, val in pkt.flags.items():
                if val:
                    attr = f"{flag.lower()}_count"
                    if hasattr(flow, attr):
                        setattr(flow, attr, getattr(flow, attr) + 1)

            flow.last_seen = pkt.timestamp
            return flow

    def get_completed_flows(self) -> List[FlowRecord]:
        """Drain and return recently completed (evicted) flows."""
        with self._lock:
            completed = list(self._completed_flows)
            self._completed_flows.clear()
            return completed

    def get_active_count(self) -> int:
        with self._lock:
            return len(self._flows)

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    @staticmethod
    def _make_key(pkt: PacketRecord) -> FlowKey:
        return (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol.value)

    @staticmethod
    def _make_reverse_key(pkt: PacketRecord) -> FlowKey:
        return (pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.protocol.value)

    def _eviction_loop(self):
        """Periodically remove idle flows and move them to completed list."""
        while True:
            time.sleep(self.eviction_interval)
            now = time.time()
            with self._lock:
                expired = [key for key, flow in self._flows.items() if now - flow.last_seen > self.flow_timeout]
                for key in expired:
                    self._completed_flows.append(self._flows.pop(key))
            if expired:
                logger.debug("Evicted %d expired flows", len(expired))
