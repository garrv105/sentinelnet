"""
Tests: ResponseManager, IncidentLogger, IPBlocker
"""

import json
import os
import tempfile
import time
import uuid

import pytest

from sentinelnet.core.event_bus import EventBus, Severity, ThreatEvent
from sentinelnet.responders.response_manager import BaseResponder, IncidentLogger, IPBlocker, ResponseManager


def make_event(severity=Severity.HIGH, threat_type="port_scan", src="10.0.0.1", score=0.9) -> ThreatEvent:
    return ThreatEvent(
        event_id=str(uuid.uuid4()),
        source="test",
        severity=severity,
        threat_type=threat_type,
        src_ip=src,
        dst_ip="192.168.1.1",
        score=score,
        description="test",
    )


class TestIncidentLogger:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.logger = IncidentLogger(log_dir=self.tmpdir)

    def test_responds_to_all_severities(self):
        for sev in Severity:
            e = make_event(severity=sev)
            assert self.logger.can_respond(e)

    def test_event_written_to_ndjson(self):
        event = make_event()
        self.logger.respond(event)
        ndjson_path = os.path.join(self.tmpdir, "incidents.ndjson")
        assert os.path.exists(ndjson_path)
        with open(ndjson_path) as f:
            line = f.readline()
        data = json.loads(line)
        assert data["event_id"] == event.event_id

    def test_event_written_to_db(self):
        event = make_event(threat_type="syn_flood", src="1.2.3.4")
        self.logger.respond(event)
        results = self.logger.query(threat_type="syn_flood")
        assert len(results) == 1
        assert results[0]["src_ip"] == "1.2.3.4"

    def test_query_by_severity(self):
        self.logger.respond(make_event(severity=Severity.CRITICAL))
        self.logger.respond(make_event(severity=Severity.LOW))
        results = self.logger.query(severity="CRITICAL")
        assert all(r["severity"] == "CRITICAL" for r in results)

    def test_query_by_src_ip(self):
        self.logger.respond(make_event(src="10.10.10.10"))
        self.logger.respond(make_event(src="20.20.20.20"))
        results = self.logger.query(src_ip="10.10.10.10")
        assert len(results) == 1

    def test_duplicate_event_id_ignored(self):
        event = make_event()
        self.logger.respond(event)
        self.logger.respond(event)  # Same event_id, should be ignored (INSERT OR IGNORE)
        results = self.logger.query()
        assert len(results) == 1

    def test_query_limit(self):
        for _ in range(20):
            self.logger.respond(make_event())
        results = self.logger.query(limit=5)
        assert len(results) == 5

    def test_evidence_json_preserved(self):
        event = make_event()
        event.evidence = {"packets": 500, "rate": 99.9}
        self.logger.respond(event)
        results = self.logger.query()
        evidence = json.loads(results[0]["evidence"])
        assert evidence["packets"] == 500


class TestIPBlocker:
    def setup_method(self):
        self.blocker = IPBlocker(
            whitelist=["127.0.0.1", "192.168.0.1"],
            block_duration_secs=10,
            dry_run=True,
        )

    def test_blocks_malicious_ip(self):
        event = make_event(src="10.0.0.99")
        self.blocker.respond(event)
        blocklist = self.blocker.get_blocklist()
        ips = [b["ip"] for b in blocklist]
        assert "10.0.0.99" in ips

    def test_whitelist_not_blocked(self):
        event = make_event(src="127.0.0.1")
        self.blocker.respond(event)
        blocklist = self.blocker.get_blocklist()
        assert len(blocklist) == 0

    def test_double_block_no_duplicate(self):
        event = make_event(src="10.0.0.50")
        self.blocker.respond(event)
        self.blocker.respond(event)
        blocklist = self.blocker.get_blocklist()
        assert sum(1 for b in blocklist if b["ip"] == "10.0.0.50") == 1

    def test_unblock_removes_ip(self):
        event = make_event(src="10.0.0.77")
        self.blocker.respond(event)
        self.blocker.unblock("10.0.0.77")
        blocklist = self.blocker.get_blocklist()
        assert "10.0.0.77" not in [b["ip"] for b in blocklist]

    def test_min_severity_filter(self):
        low_event = make_event(severity=Severity.LOW)
        assert not self.blocker.can_respond(low_event)
        high_event = make_event(severity=Severity.HIGH)
        assert self.blocker.can_respond(high_event)

    def test_ttl_in_blocklist(self):
        event = make_event(src="99.99.99.99")
        self.blocker.respond(event)
        blocklist = self.blocker.get_blocklist()
        entry = next(b for b in blocklist if b["ip"] == "99.99.99.99")
        assert 0 <= entry["expires_in_secs"] <= 10


class TestResponseManager:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.bus = EventBus()
        self.manager = ResponseManager(
            bus=self.bus,
            config={
                "log_dir": self.tmpdir,
                "enable_ip_blocker": True,
                "dry_run": True,
                "ip_whitelist": ["127.0.0.1"],
            },
        )

    def teardown_method(self):
        self.bus.shutdown()

    def test_incident_logged_on_event(self):
        event = make_event(severity=Severity.HIGH)
        self.bus.publish_sync(event)
        results = self.manager.query_incidents()
        assert len(results) >= 1

    def test_custom_responder_added(self):
        class DummyResponder(BaseResponder):
            name = "dummy"
            calls = []

            def respond(self, e):
                self.calls.append(e)

        dr = DummyResponder()
        self.manager.add_responder(dr)
        event = make_event()
        self.bus.publish_sync(event)
        assert len(dr.calls) == 1
