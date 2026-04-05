"""
Tests: PacketCaptureEngine and PacketRecord
"""

import queue
import time

import pytest

from sentinelnet.core.packet_capture import PacketCaptureEngine, PacketRecord, Protocol


def make_packet(**kwargs) -> PacketRecord:
    defaults = dict(
        timestamp=time.time(),
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=443,
        protocol=Protocol.HTTPS,
        length=512,
        flags={"SYN": False, "ACK": True},
        payload_size=480,
        ttl=64,
    )
    defaults.update(kwargs)
    return PacketRecord(**defaults)


class TestPacketRecord:
    def test_to_dict_contains_required_keys(self):
        pkt = make_packet()
        d = pkt.to_dict()
        for key in [
            "timestamp",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "length",
            "flags",
            "payload_size",
            "ttl",
        ]:
            assert key in d, f"Missing key: {key}"

    def test_protocol_value_serialization(self):
        pkt = make_packet(protocol=Protocol.DNS)
        assert pkt.to_dict()["protocol"] == "DNS"

    def test_flags_preserved(self):
        flags = {"SYN": True, "ACK": False, "FIN": False, "RST": False}
        pkt = make_packet(flags=flags)
        assert pkt.to_dict()["flags"]["SYN"] is True
        assert pkt.to_dict()["flags"]["ACK"] is False

    def test_default_fields(self):
        pkt = make_packet()
        assert pkt.ttl == 64
        assert isinstance(pkt.metadata, dict)

    @pytest.mark.parametrize("proto", list(Protocol))
    def test_all_protocols_serializable(self, proto):
        pkt = make_packet(protocol=proto)
        d = pkt.to_dict()
        assert d["protocol"] == proto.value


class TestPacketCaptureEngine:
    def test_engine_initializes(self):
        q = queue.Queue()
        engine = PacketCaptureEngine(pcap_file="nonexistent.pcap", packet_queue=q)
        assert engine is not None
        assert engine.max_queue_size == 10000

    def test_get_stats_initial(self):
        engine = PacketCaptureEngine(interface="lo")
        stats = engine.get_stats()
        assert stats["captured"] == 0
        assert stats["parsed"] == 0
        assert stats["dropped"] == 0
        assert stats["errors"] == 0

    def test_register_callback(self):
        engine = PacketCaptureEngine(interface="lo")
        called = []
        engine.register_callback(lambda p: called.append(p))
        assert len(engine._callbacks) == 1

    def test_custom_queue_injected(self):
        q = queue.Queue(maxsize=5)
        engine = PacketCaptureEngine(interface="lo", packet_queue=q)
        assert engine.packet_queue is q
