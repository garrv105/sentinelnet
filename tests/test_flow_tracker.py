"""
Tests: FlowTracker — flow aggregation, IAT calculation, flag counting, eviction
"""
import time
import pytest
from sentinelnet.core.packet_capture import PacketRecord, Protocol
from sentinelnet.core.flow_tracker import FlowTracker, FlowRecord


def make_pkt(src="1.2.3.4", dst="5.6.7.8", sport=1234, dport=80,
             proto=Protocol.TCP, length=100, payload=50,
             flags=None, ts=None) -> PacketRecord:
    return PacketRecord(
        timestamp=ts or time.time(),
        src_ip=src, dst_ip=dst,
        src_port=sport, dst_port=dport,
        protocol=proto,
        length=length,
        flags=flags or {"SYN": False, "ACK": True},
        payload_size=payload,
        ttl=64,
    )


class TestFlowTracker:
    def setup_method(self):
        self.tracker = FlowTracker(flow_timeout=300.0, eviction_interval=9999)

    def test_single_packet_creates_flow(self):
        pkt = make_pkt()
        flow = self.tracker.update(pkt)
        assert flow is not None
        assert flow.src_ip == "1.2.3.4"
        assert flow.fwd_packets == 1
        assert flow.fwd_bytes == 100

    def test_second_packet_same_dir_aggregates(self):
        pkt1 = make_pkt(ts=1000.0)
        pkt2 = make_pkt(ts=1001.0)
        self.tracker.update(pkt1)
        flow = self.tracker.update(pkt2)
        assert flow.fwd_packets == 2
        assert flow.fwd_bytes == 200

    def test_reverse_packet_counted_as_bwd(self):
        pkt_fwd = make_pkt(src="1.2.3.4", dst="5.6.7.8", sport=1234, dport=80, ts=1000.0)
        pkt_bwd = make_pkt(src="5.6.7.8", dst="1.2.3.4", sport=80, dport=1234, ts=1001.0)
        self.tracker.update(pkt_fwd)
        flow = self.tracker.update(pkt_bwd)
        assert flow.bwd_packets == 1
        assert flow.bwd_bytes == 100

    def test_syn_flag_counted(self):
        pkt = make_pkt(flags={"SYN": True, "ACK": False, "FIN": False, "RST": False,
                               "PSH": False, "URG": False})
        flow = self.tracker.update(pkt)
        assert flow.syn_count == 1

    def test_iat_recorded_on_second_packet(self):
        pkt1 = make_pkt(ts=1000.0)
        pkt2 = make_pkt(ts=1001.0)
        self.tracker.update(pkt1)
        flow = self.tracker.update(pkt2)
        assert len(flow.fwd_iat) == 1
        assert abs(flow.fwd_iat[0] - 1000.0) < 1.0  # ~1000ms

    def test_active_count(self):
        self.tracker.update(make_pkt(src="1.1.1.1"))
        self.tracker.update(make_pkt(src="2.2.2.2"))
        assert self.tracker.get_active_count() == 2

    def test_max_flows_enforced(self):
        tracker = FlowTracker(max_flows=2, eviction_interval=9999)
        tracker.update(make_pkt(src="1.1.1.1", sport=1))
        tracker.update(make_pkt(src="2.2.2.2", sport=2))
        result = tracker.update(make_pkt(src="3.3.3.3", sport=3))
        assert result is None  # Dropped

    def test_flow_feature_vector_shape(self):
        pkt = make_pkt(ts=1000.0)
        self.tracker.update(pkt)
        self.tracker.update(make_pkt(ts=1001.0))
        flows = list(self.tracker._flows.values())
        vec = flows[0].to_feature_vector()
        assert isinstance(vec, dict)
        assert "duration" in vec
        assert "bytes_per_sec" in vec
        assert "flag_ratio" in vec

    def test_flow_duration_positive(self):
        pkt1 = make_pkt(ts=1000.0)
        pkt2 = make_pkt(ts=1002.0)
        self.tracker.update(pkt1)
        flow = self.tracker.update(pkt2)
        assert flow.duration > 0

    def test_to_dict_completeness(self):
        self.tracker.update(make_pkt())
        flow = list(self.tracker._flows.values())[0]
        d = flow.to_dict()
        for k in ["src_ip", "dst_ip", "duration", "fwd_packets", "bytes_per_sec"]:
            assert k in d


class TestFlowRecord:
    def test_flag_ratio_no_division_by_zero(self):
        flow = FlowRecord(
            key=("a", "b", 1, 2, "TCP"),
            src_ip="a", dst_ip="b", src_port=1, dst_port=2, protocol="TCP"
        )
        assert flow.flag_ratio == 0.0  # syn=0, ack=0 → 0/1 = 0

    def test_bytes_per_second(self):
        flow = FlowRecord(
            key=("a", "b", 1, 2, "TCP"),
            src_ip="a", dst_ip="b", src_port=1, dst_port=2, protocol="TCP",
            start_time=0.0, last_seen=1.0,
            fwd_bytes=1000, bwd_bytes=500,
        )
        assert flow.bytes_per_second == 1500.0

    def test_total_packets(self):
        flow = FlowRecord(
            key=("a", "b", 1, 2, "TCP"),
            src_ip="a", dst_ip="b", src_port=1, dst_port=2, protocol="TCP",
            fwd_packets=10, bwd_packets=5,
        )
        assert flow.total_packets == 15
