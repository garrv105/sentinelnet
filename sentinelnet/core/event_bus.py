"""
SentinelNet - Internal Event Bus
===================================
Lightweight pub/sub system for decoupling detection, alerting, and response.
Supports synchronous and async subscribers with priority ordering.
"""

import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List

logger = logging.getLogger(__name__)


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def label(self) -> str:
        return self.name


@dataclass
class ThreatEvent:
    """Unified threat event emitted by any detector."""

    event_id: str
    source: str  # detector name
    severity: Severity
    threat_type: str  # e.g. "port_scan", "syn_flood", "dns_tunnel"
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    score: float = 0.0  # confidence 0-1
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    mitre_tactic: str = ""  # MITRE ATT&CK tactic tag
    mitre_technique: str = ""  # MITRE ATT&CK technique tag

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "source": self.source,
            "severity": self.severity.label(),
            "severity_value": int(self.severity),
            "threat_type": self.threat_type,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "score": round(self.score, 4),
            "description": self.description,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
        }


@dataclass(order=True)
class _PrioritizedEvent:
    priority: int
    event: ThreatEvent = field(compare=False)


class EventBus:
    """
    Thread-safe publish/subscribe event bus.

    Subscribers register interest in specific threat types or all events.
    Events are dispatched to subscribers asynchronously via worker threads.

    Usage:
        bus = EventBus()
        bus.subscribe("port_scan", my_handler)
        bus.subscribe("*", audit_logger)
        bus.publish(threat_event)
    """

    def __init__(self, workers: int = 2, max_queue: int = 50_000):
        self._subscribers: Dict[str, List[Callable[[ThreatEvent], None]]] = {}
        self._lock = threading.RLock()
        self._event_queue: queue.PriorityQueue = queue.PriorityQueue(maxsize=max_queue)
        self._workers = workers
        self._running = True
        self._stats = {"published": 0, "dispatched": 0, "dropped": 0}

        for i in range(workers):
            t = threading.Thread(target=self._dispatch_loop, name=f"eventbus-{i}", daemon=True)
            t.start()

    def subscribe(self, threat_type: str, handler: Callable[[ThreatEvent], None]):
        """
        Subscribe to a specific threat type or '*' for all events.
        Multiple handlers per type are supported.
        """
        with self._lock:
            self._subscribers.setdefault(threat_type, []).append(handler)
        logger.debug("Subscribed %s to event type '%s'", handler.__name__, threat_type)

    def unsubscribe(self, threat_type: str, handler: Callable[[ThreatEvent], None]):
        with self._lock:
            handlers = self._subscribers.get(threat_type, [])
            if handler in handlers:
                handlers.remove(handler)

    def publish(self, event: ThreatEvent):
        """Enqueue an event for async dispatch."""
        priority = -int(event.severity)  # Higher severity = lower priority number = dispatched first
        try:
            self._event_queue.put_nowait(_PrioritizedEvent(priority=priority, event=event))
            self._stats["published"] += 1
        except queue.Full:
            self._stats["dropped"] += 1
            logger.warning("EventBus queue full, dropping event: %s", event.event_id)

    def publish_sync(self, event: ThreatEvent):
        """Synchronously dispatch an event to all subscribers (blocks)."""
        self._dispatch_event(event)

    def get_stats(self) -> Dict[str, int]:
        return dict(self._stats)

    def shutdown(self):
        self._running = False
        for _ in range(self._workers):
            self._event_queue.put(_PrioritizedEvent(priority=0, event=None))  # type: ignore

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _dispatch_loop(self):
        while self._running:
            try:
                item = self._event_queue.get(timeout=1.0)
                if item.event is None:
                    break
                self._dispatch_event(item.event)
            except queue.Empty:
                continue

    def _dispatch_event(self, event: ThreatEvent):
        with self._lock:
            specific = list(self._subscribers.get(event.threat_type, []))
            wildcard = list(self._subscribers.get("*", []))

        all_handlers = specific + wildcard
        for handler in all_handlers:
            try:
                handler(event)
                self._stats["dispatched"] += 1
            except Exception as e:
                logger.error("Event handler %s raised: %s", handler.__name__, e)
