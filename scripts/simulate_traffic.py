"""
SentinelNet - Traffic Simulation Script
=========================================
Generates realistic synthetic network traffic including:
- Normal HTTP/HTTPS/DNS traffic
- Port scan attacks
- SYN flood attacks
- DNS tunneling patterns
- Brute force attempts
- Data exfiltration flows

Writes to a PCAP file or directly feeds the engine's queue.
Use for testing without root privileges.
"""

import argparse
import json
import queue
import random
import time
from typing import List

# Try scapy for real PCAP output
try:
    from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Packet, Raw, wrpcap  # noqa: F401

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from sentinelnet.core.packet_capture import PacketRecord, Protocol


def random_ip(prefix: str = None) -> str:
    if prefix:
        return f"{prefix}.{random.randint(1,254)}.{random.randint(1,254)}"
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def make_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: Protocol,
    length: int = 64,
    flags: dict = None,
    payload_size: int = 0,
    ttl: int = 64,
    timestamp: float = None,
) -> PacketRecord:
    return PacketRecord(
        timestamp=timestamp or time.time(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
        flags=flags or {},
        payload_size=payload_size,
        ttl=ttl,
    )


class TrafficSimulator:
    """
    Generates synthetic network traffic scenarios.
    Can output to:
    1. A PacketRecord queue (direct engine injection)
    2. NDJSON file (for offline analysis)
    3. PCAP file (if Scapy is available)
    """

    def __init__(self, output_queue: queue.Queue = None, output_file: str = None):
        self.output_queue = output_queue
        self.output_file = output_file
        self._packets: List[PacketRecord] = []
        self._start_time = time.time()

    def emit(self, pkt: PacketRecord):
        if self.output_queue:
            self.output_queue.put(pkt)
        self._packets.append(pkt)

    def generate_normal_traffic(self, n: int = 500, src_prefix: str = "192.168.1"):
        """Generate realistic background HTTP/HTTPS/DNS traffic."""
        print(f"  Generating {n} normal traffic packets...")
        servers = ["8.8.8.8", "1.1.1.1", "142.250.64.100", "151.101.1.67"]
        for i in range(n):
            src = f"{src_prefix}.{random.randint(2, 50)}"
            dst = random.choice(servers)
            proto = random.choice([Protocol.HTTP, Protocol.HTTPS, Protocol.DNS])
            port_map = {Protocol.HTTP: 80, Protocol.HTTPS: 443, Protocol.DNS: 53}
            self.emit(
                make_packet(
                    src_ip=src,
                    dst_ip=dst,
                    src_port=random.randint(49152, 65535),
                    dst_port=port_map[proto],
                    protocol=proto,
                    length=random.randint(64, 1500),
                    flags={"SYN": False, "ACK": True},
                    payload_size=random.randint(20, 800),
                    timestamp=self._start_time + i * 0.1,
                )
            )

    def simulate_port_scan(self, attacker: str = "10.0.0.99", victim_prefix: str = "192.168.1"):
        """Simulate horizontal port scan (Nmap-like)."""
        print(f"  Simulating port scan from {attacker}...")
        ts = self._start_time + 10
        for i in range(50):
            dst_ip = f"{victim_prefix}.{i + 1}"
            self.emit(
                make_packet(
                    src_ip=attacker,
                    dst_ip=dst_ip,
                    src_port=random.randint(49152, 65535),
                    dst_port=80,
                    protocol=Protocol.TCP,
                    length=40,
                    flags={"SYN": True, "ACK": False},
                    timestamp=ts + i * 0.02,
                )
            )

    def simulate_syn_flood(self, attacker: str = "203.0.113.5", victim: str = "192.168.1.10"):
        """Simulate TCP SYN flood DoS attack."""
        print(f"  Simulating SYN flood from {attacker} → {victim}...")
        ts = self._start_time + 20
        for i in range(200):
            src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            self.emit(
                make_packet(
                    src_ip=src_ip,
                    dst_ip=victim,
                    src_port=random.randint(1024, 65535),
                    dst_port=80,
                    protocol=Protocol.TCP,
                    length=40,
                    flags={"SYN": True, "ACK": False},
                    timestamp=ts + i * 0.01,
                )
            )

    def simulate_brute_force(self, attacker: str = "185.234.219.11", victim: str = "192.168.1.5"):
        """Simulate SSH brute force."""
        print(f"  Simulating SSH brute force from {attacker} → {victim}:22...")
        ts = self._start_time + 30
        for i in range(60):
            self.emit(
                make_packet(
                    src_ip=attacker,
                    dst_ip=victim,
                    src_port=random.randint(49152, 65535),
                    dst_port=22,
                    protocol=Protocol.TCP,
                    length=80,
                    flags={"SYN": True, "ACK": False},
                    timestamp=ts + i * 0.5,
                )
            )

    def simulate_dns_tunneling(self, attacker: str = "172.16.5.50", dns_server: str = "8.8.8.8"):
        """Simulate DNS tunneling (high-frequency, large payload)."""
        print(f"  Simulating DNS tunneling from {attacker}...")
        ts = self._start_time + 40
        for i in range(120):
            self.emit(
                make_packet(
                    src_ip=attacker,
                    dst_ip=dns_server,
                    src_port=random.randint(49152, 65535),
                    dst_port=53,
                    protocol=Protocol.DNS,
                    length=random.randint(200, 512),
                    payload_size=random.randint(150, 480),
                    timestamp=ts + i * 0.5,
                )
            )

    def save_ndjson(self, path: str):
        """Save all packets as NDJSON."""
        with open(path, "w") as f:
            for pkt in self._packets:
                f.write(json.dumps(pkt.to_dict()) + "\n")
        print(f"\n  Saved {len(self._packets)} packets to {path}")

    def get_summary(self) -> dict:
        proto_counts = {}
        for pkt in self._packets:
            k = pkt.protocol.value
            proto_counts[k] = proto_counts.get(k, 0) + 1
        return {
            "total_packets": len(self._packets),
            "protocols": proto_counts,
            "time_span_secs": (
                max(p.timestamp for p in self._packets) - min(p.timestamp for p in self._packets)
                if self._packets
                else 0
            ),
        }


def main():
    parser = argparse.ArgumentParser(description="SentinelNet Traffic Simulator")
    parser.add_argument("--output", default="simulation.ndjson", help="Output NDJSON file")
    parser.add_argument("--normal", type=int, default=500, help="Normal traffic packets")
    parser.add_argument("--attacks", action="store_true", help="Include attack scenarios")
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  SentinelNet Traffic Simulator")
    print("=" * 60)

    sim = TrafficSimulator()
    sim.generate_normal_traffic(n=args.normal)

    if args.attacks:
        sim.simulate_port_scan()
        sim.simulate_syn_flood()
        sim.simulate_brute_force()
        sim.simulate_dns_tunneling()

    sim.save_ndjson(args.output)
    summary = sim.get_summary()

    print("\n  Simulation Summary:")
    print(f"    Total packets : {summary['total_packets']}")
    print(f"    Time span     : {summary['time_span_secs']:.1f}s")
    print(f"    Protocols     : {summary['protocols']}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
