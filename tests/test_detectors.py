"""
Tests: Rule-based detectors — port scan, SYN flood, brute force, DNS tunneling
"""

import time

import pytest

from sentinelnet.core.event_bus import EventBus, Severity
from sentinelnet.core.packet_capture import PacketRecord, Protocol
from sentinelnet.detectors.rule_engine import (
    BruteForceDetector,
    DNSTunnelingDetector,
    PortScanDetector,
    RuleEngine,
    SynFloodDetector,
)


def make_pkt(
    src="10.0.0.1", dst="192.168.1.1", sport=54321, dport=80, proto=Protocol.TCP, flags=None, payload=0, ts=None
) -> PacketRecord:
    return PacketRecord(
        timestamp=ts or time.time(),
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        protocol=proto,
        length=64,
        flags=flags or {},
        payload_size=payload,
        ttl=64,
    )


class TestPortScanDetector:
    def setup_method(self):
        self.detector = PortScanDetector(
            window_secs=60.0,
            horizontal_threshold=10,
            vertical_threshold=8,
        )

    def test_no_alert_on_normal_traffic(self):
        pkt = make_pkt(dst="192.168.1.1")
        assert self.detector.inspect(pkt) is None

    def test_horizontal_scan_detected(self):
        base_ts = time.time()
        event = None
        for i in range(15):
            pkt = make_pkt(dst=f"192.168.1.{i+1}", ts=base_ts + i * 0.1)
            event = self.detector.inspect(pkt)
        assert event is not None
        assert event.threat_type == "horizontal_port_scan"
        assert event.severity == Severity.HIGH

    def test_vertical_scan_detected(self):
        base_ts = time.time()
        event = None
        for port in range(20, 30):
            pkt = make_pkt(dport=port, ts=base_ts + port * 0.01)
            event = self.detector.inspect(pkt)
        assert event is not None
        assert event.threat_type == "vertical_port_scan"

    def test_scan_score_bounded(self):
        base_ts = time.time()
        event = None
        for i in range(50):
            pkt = make_pkt(dst=f"10.0.0.{i+1}", ts=base_ts + i * 0.01)
            event = self.detector.inspect(pkt)
        assert event is not None
        assert 0.0 <= event.score <= 1.0

    def test_mitre_tag_set(self):
        base_ts = time.time()
        event = None
        for i in range(15):
            pkt = make_pkt(dst=f"10.0.{i}.1", ts=base_ts + i * 0.05)
            event = self.detector.inspect(pkt)
        if event:
            assert event.mitre_technique == "T1046"

    def test_window_expiry_resets_counter(self):
        """Events outside the window should not contribute to the count."""
        detector = PortScanDetector(window_secs=1.0, horizontal_threshold=10)
        old_ts = time.time() - 60
        for i in range(15):
            pkt = make_pkt(dst=f"10.0.0.{i}", ts=old_ts + i * 0.01)
            detector.inspect(pkt)
        # New packet with current timestamp — old events have expired
        new_pkt = make_pkt(dst="10.0.0.100", ts=time.time())
        result = detector.inspect(new_pkt)
        assert result is None


class TestSynFloodDetector:
    def setup_method(self):
        self.detector = SynFloodDetector(window_secs=10.0, syn_threshold=20)

    def test_no_alert_normal_traffic(self):
        pkt = make_pkt(flags={"SYN": True, "ACK": True})  # SYN-ACK, not a SYN
        assert self.detector.inspect(pkt) is None

    def test_syn_flood_detected(self):
        base_ts = time.time()
        event = None
        for i in range(25):
            pkt = make_pkt(
                flags={"SYN": True, "ACK": False},
                proto=Protocol.TCP,
                ts=base_ts + i * 0.1,
            )
            event = self.detector.inspect(pkt)
        assert event is not None
        assert event.threat_type == "syn_flood"
        assert event.severity == Severity.CRITICAL

    def test_ack_only_not_flagged(self):
        base_ts = time.time()
        for i in range(50):
            pkt = make_pkt(
                flags={"SYN": False, "ACK": True},
                proto=Protocol.TCP,
                ts=base_ts + i * 0.01,
            )
            result = self.detector.inspect(pkt)
            assert result is None

    def test_udp_ignored(self):
        base_ts = time.time()
        for i in range(50):
            pkt = make_pkt(proto=Protocol.UDP, flags={"SYN": True}, ts=base_ts + i * 0.01)
            result = self.detector.inspect(pkt)
            assert result is None


class TestBruteForceDetector:
    def setup_method(self):
        self.detector = BruteForceDetector(window_secs=60.0, attempt_threshold=10)

    def test_ssh_brute_force_detected(self):
        base_ts = time.time()
        event = None
        for i in range(15):
            pkt = make_pkt(
                dport=22,
                proto=Protocol.TCP,
                flags={"SYN": True, "ACK": False},
                ts=base_ts + i * 1.0,
            )
            event = self.detector.inspect(pkt)
        assert event is not None
        assert event.threat_type == "brute_force"
        assert event.evidence["service"] == "SSH"

    def test_rdp_brute_force_detected(self):
        base_ts = time.time()
        event = None
        for i in range(15):
            pkt = make_pkt(
                dport=3389,
                proto=Protocol.TCP,
                flags={"SYN": True, "ACK": False},
                ts=base_ts + i * 0.5,
            )
            event = self.detector.inspect(pkt)
        assert event is not None
        assert event.evidence["service"] == "RDP"

    def test_non_auth_port_ignored(self):
        base_ts = time.time()
        for i in range(30):
            pkt = make_pkt(
                dport=8080,
                proto=Protocol.TCP,
                flags={"SYN": True},
                ts=base_ts + i * 0.1,
            )
            result = self.detector.inspect(pkt)
            assert result is None

    def test_mitre_technique(self):
        base_ts = time.time()
        event = None
        for i in range(15):
            pkt = make_pkt(dport=22, proto=Protocol.TCP, flags={"SYN": True, "ACK": False}, ts=base_ts + i)
            event = self.detector.inspect(pkt)
        if event:
            assert event.mitre_technique == "T1110"


class TestDNSTunnelingDetector:
    def setup_method(self):
        self.detector = DNSTunnelingDetector(
            window_secs=60.0,
            rate_threshold=30,
            payload_threshold=80,
        )

    def test_normal_dns_not_flagged(self):
        base_ts = time.time()
        for i in range(5):
            pkt = make_pkt(dport=53, proto=Protocol.DNS, payload=40, ts=base_ts + i)
            result = self.detector.inspect(pkt)
            assert result is None

    def test_tunneling_detected(self):
        base_ts = time.time()
        event = None
        for i in range(50):
            pkt = make_pkt(
                dport=53,
                proto=Protocol.DNS,
                payload=200,
                ts=base_ts + i * 1.0,
            )
            event = self.detector.inspect(pkt)
        assert event is not None
        assert event.threat_type == "dns_tunneling"

    def test_non_dns_ignored(self):
        base_ts = time.time()
        for i in range(50):
            pkt = make_pkt(proto=Protocol.TCP, payload=200, ts=base_ts + i * 0.5)
            result = self.detector.inspect(pkt)
            assert result is None


class TestRuleEngine:
    def setup_method(self):
        self.bus = EventBus()
        self.events = []
        self.bus.subscribe("*", lambda e: self.events.append(e))
        self.engine = RuleEngine(bus=self.bus)

    def teardown_method(self):
        self.bus.shutdown()

    def test_rule_engine_initializes(self):
        assert len(self.engine._detectors) == 4

    def test_inspect_packet_no_crash(self):
        pkt = make_pkt()
        self.engine.inspect_packet(pkt)  # Should not raise

    def test_dedup_prevents_duplicate_events(self):
        """Same src+threat should not emit twice within cooldown."""
        self.engine._dedup_cooldown = 999.0  # very long cooldown
        base_ts = time.time()
        for i in range(30):
            pkt = make_pkt(dst=f"192.168.1.{i}", ts=base_ts + i * 0.1)
            self.engine.inspect_packet(pkt)
        import time as t

        t.sleep(0.5)  # let bus dispatch
        scan_events = [e for e in self.events if "scan" in e.threat_type]
        # Should only get 1 despite many packets (dedup kicks in)
        assert len(scan_events) <= 1
