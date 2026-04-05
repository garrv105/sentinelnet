"""
SentinelNet - Packet Capture Engine
====================================
Real-time network packet capture with multi-threaded processing pipeline.
Supports live interface capture and PCAP file replay.
"""

import logging
import threading
import queue
import time
from dataclasses import dataclass, field
from typing import Optional, Callable, List, Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)


class Protocol(Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ARP = "ARP"
    DNS = "DNS"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    UNKNOWN = "UNKNOWN"


@dataclass
class PacketRecord:
    """Normalized packet representation for the detection pipeline."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Protocol
    length: int
    flags: Dict[str, bool] = field(default_factory=dict)
    payload_size: int = 0
    ttl: int = 64
    raw_summary: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol.value,
            "length": self.length,
            "flags": self.flags,
            "payload_size": self.payload_size,
            "ttl": self.ttl,
            "raw_summary": self.raw_summary,
            "metadata": self.metadata,
        }


class PacketCaptureEngine:
    """
    Multi-threaded packet capture engine.

    Supports:
    - Live capture via Scapy (requires root/admin)
    - PCAP file replay for testing and forensics
    - Pluggable packet handler callbacks
    - Thread-safe packet queue with backpressure

    Architecture:
        CaptureThread → RawQueue → ParseThread → ParsedQueue → DetectionPipeline
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        packet_queue: Optional[queue.Queue] = None,
        bpf_filter: str = "",
        max_queue_size: int = 10000,
        workers: int = 4,
    ):
        self.interface = interface
        self.pcap_file = pcap_file
        self.bpf_filter = bpf_filter
        self.max_queue_size = max_queue_size
        self.workers = workers

        self._raw_queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self.packet_queue: queue.Queue = packet_queue or queue.Queue(maxsize=max_queue_size)

        self._running = False
        self._threads: List[threading.Thread] = []
        self._stats = {
            "captured": 0,
            "parsed": 0,
            "dropped": 0,
            "errors": 0,
        }
        self._callbacks: List[Callable[[PacketRecord], None]] = []

    def register_callback(self, fn: Callable[[PacketRecord], None]):
        """Register a synchronous callback invoked for each parsed packet."""
        self._callbacks.append(fn)

    def start(self):
        """Start capture and parse threads."""
        self._running = True
        logger.info(
            "PacketCaptureEngine starting | interface=%s pcap=%s filter='%s'",
            self.interface, self.pcap_file, self.bpf_filter,
        )

        # Capture thread
        if self.pcap_file:
            t = threading.Thread(target=self._replay_pcap, name="pcap-replay", daemon=True)
        else:
            t = threading.Thread(target=self._live_capture, name="live-capture", daemon=True)
        self._threads.append(t)
        t.start()

        # Parser worker threads
        for i in range(self.workers):
            pt = threading.Thread(target=self._parse_worker, name=f"parser-{i}", daemon=True)
            self._threads.append(pt)
            pt.start()

    def stop(self):
        """Gracefully stop all threads."""
        logger.info("PacketCaptureEngine stopping...")
        self._running = False
        for _ in range(self.workers):
            self._raw_queue.put(None)  # Poison pills
        for t in self._threads:
            t.join(timeout=5.0)
        logger.info("PacketCaptureEngine stopped | stats=%s", self._stats)

    def get_stats(self) -> Dict[str, int]:
        return dict(self._stats)

    # ------------------------------------------------------------------
    # Private methods
    # ------------------------------------------------------------------

    def _live_capture(self):
        """Live interface capture using Scapy."""
        try:
            from scapy.all import sniff
        except ImportError:
            logger.error("Scapy not installed. Install with: pip install scapy")
            return

        def _handler(pkt):
            if not self._running:
                return
            try:
                self._raw_queue.put_nowait(pkt)
                self._stats["captured"] += 1
            except queue.Full:
                self._stats["dropped"] += 1
                logger.debug("Raw queue full, dropping packet")

        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter or None,
                prn=_handler,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            logger.error("Live capture error: %s", e)

    def _replay_pcap(self):
        """Replay packets from a PCAP file."""
        try:
            from scapy.all import PcapReader
        except ImportError:
            logger.error("Scapy not installed.")
            return

        try:
            with PcapReader(self.pcap_file) as reader:
                for pkt in reader:
                    if not self._running:
                        break
                    try:
                        self._raw_queue.put_nowait(pkt)
                        self._stats["captured"] += 1
                    except queue.Full:
                        self._stats["dropped"] += 1
        except Exception as e:
            logger.error("PCAP replay error: %s", e)
        finally:
            # Signal end of file
            for _ in range(self.workers):
                self._raw_queue.put(None)

    def _parse_worker(self):
        """Worker thread: parse raw Scapy packets into PacketRecord."""
        while self._running:
            try:
                raw = self._raw_queue.get(timeout=1.0)
                if raw is None:
                    break
                record = self._parse_packet(raw)
                if record:
                    self.packet_queue.put(record)
                    for cb in self._callbacks:
                        try:
                            cb(record)
                        except Exception as e:
                            logger.warning("Callback error: %s", e)
                    self._stats["parsed"] += 1
            except queue.Empty:
                continue
            except Exception as e:
                self._stats["errors"] += 1
                logger.debug("Parse error: %s", e)

    def _parse_packet(self, pkt) -> Optional[PacketRecord]:
        """Convert a Scapy packet to a normalized PacketRecord."""
        try:
            from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, Raw

            ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
            src_ip = dst_ip = "0.0.0.0"
            src_port = dst_port = 0
            protocol = Protocol.UNKNOWN
            flags = {}
            ttl = 64
            payload_size = 0

            if pkt.haslayer(IP):
                ip = pkt[IP]
                src_ip = ip.src
                dst_ip = ip.dst
                ttl = ip.ttl

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                protocol = Protocol.HTTPS if dst_port == 443 else (
                    Protocol.HTTP if dst_port in (80, 8080) else Protocol.TCP
                )
                flags = {
                    "SYN": bool(tcp.flags & 0x02),
                    "ACK": bool(tcp.flags & 0x10),
                    "FIN": bool(tcp.flags & 0x01),
                    "RST": bool(tcp.flags & 0x04),
                    "PSH": bool(tcp.flags & 0x08),
                    "URG": bool(tcp.flags & 0x20),
                }
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                src_port = udp.sport
                dst_port = udp.dport
                protocol = Protocol.DNS if dst_port == 53 else Protocol.UDP
            elif pkt.haslayer(ICMP):
                protocol = Protocol.ICMP
            elif pkt.haslayer(ARP):
                protocol = Protocol.ARP
                src_ip = pkt[ARP].psrc
                dst_ip = pkt[ARP].pdst

            if pkt.haslayer(Raw):
                payload_size = len(bytes(pkt[Raw]))

            return PacketRecord(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=len(pkt),
                flags=flags,
                payload_size=payload_size,
                ttl=ttl,
                raw_summary=pkt.summary(),
            )
        except Exception as e:
            logger.debug("Packet parse failed: %s", e)
            return None
