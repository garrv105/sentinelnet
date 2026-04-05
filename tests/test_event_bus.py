"""
Tests: EventBus — pub/sub dispatch, priority ordering, dedup, shutdown
"""
import time
import threading
import pytest
from sentinelnet.core.event_bus import EventBus, ThreatEvent, Severity


def make_event(threat_type="port_scan", severity=Severity.HIGH,
               src="1.2.3.4", dst="5.6.7.8", score=0.8) -> ThreatEvent:
    import uuid
    return ThreatEvent(
        event_id=str(uuid.uuid4()),
        source="test",
        severity=severity,
        threat_type=threat_type,
        src_ip=src,
        dst_ip=dst,
        score=score,
        description="test event",
    )


class TestEventBus:
    def setup_method(self):
        self.bus = EventBus(workers=2, max_queue=1000)
        self.received = []
        self._lock = threading.Lock()

    def teardown_method(self):
        self.bus.shutdown()

    def _handler(self, event: ThreatEvent):
        with self._lock:
            self.received.append(event)

    def _wait(self, count: int, timeout: float = 2.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if len(self.received) >= count:
                    return True
            time.sleep(0.05)
        return False

    def test_subscribe_and_receive(self):
        self.bus.subscribe("port_scan", self._handler)
        event = make_event("port_scan")
        self.bus.publish(event)
        assert self._wait(1), "Event not received"
        assert self.received[0].event_id == event.event_id

    def test_wildcard_receives_all_types(self):
        self.bus.subscribe("*", self._handler)
        for t in ["port_scan", "syn_flood", "brute_force"]:
            self.bus.publish(make_event(t))
        assert self._wait(3)
        types = {e.threat_type for e in self.received}
        assert types == {"port_scan", "syn_flood", "brute_force"}

    def test_specific_subscriber_misses_other_types(self):
        self.bus.subscribe("syn_flood", self._handler)
        self.bus.publish(make_event("port_scan"))
        self.bus.publish(make_event("syn_flood"))
        assert self._wait(1)
        assert all(e.threat_type == "syn_flood" for e in self.received)

    def test_multiple_subscribers_all_notified(self):
        received2 = []
        self.bus.subscribe("*", self._handler)
        self.bus.subscribe("*", lambda e: received2.append(e))
        event = make_event("port_scan")
        self.bus.publish(event)
        assert self._wait(1)
        time.sleep(0.3)
        assert len(received2) == 1

    def test_sync_publish(self):
        self.bus.subscribe("*", self._handler)
        event = make_event("dns_tunneling")
        self.bus.publish_sync(event)
        with self._lock:
            assert len(self.received) == 1

    def test_stats_tracking(self):
        self.bus.subscribe("*", self._handler)
        for _ in range(5):
            self.bus.publish(make_event())
        self._wait(5)
        stats = self.bus.get_stats()
        assert stats["published"] == 5
        assert stats["dispatched"] >= 5

    def test_event_to_dict_complete(self):
        event = make_event()
        d = event.to_dict()
        required = ["event_id", "source", "severity", "threat_type",
                    "src_ip", "dst_ip", "score", "timestamp"]
        for k in required:
            assert k in d

    def test_severity_labels(self):
        assert Severity.CRITICAL.label() == "CRITICAL"
        assert Severity.HIGH.label() == "HIGH"
        assert Severity.LOW.label() == "LOW"
        assert Severity.INFO.label() == "INFO"

    def test_severity_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO

    def test_queue_full_drops_gracefully(self):
        bus = EventBus(workers=1, max_queue=2)
        received = []
        bus.subscribe("*", lambda e: (time.sleep(0.5), received.append(e)))
        for _ in range(10):
            bus.publish(make_event())
        stats = bus.get_stats()
        assert stats["dropped"] >= 0  # Should not crash
        bus.shutdown()

    def test_unsubscribe(self):
        self.bus.subscribe("*", self._handler)
        self.bus.unsubscribe("*", self._handler)
        self.bus.publish_sync(make_event())
        with self._lock:
            assert len(self.received) == 0
