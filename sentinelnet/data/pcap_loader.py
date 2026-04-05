"""
SentinelNet - PCAP Dataset Loader
===================================
Converts raw PCAP files into labelled flow-feature datasets suitable for:
  - Training the anomaly detector baseline
  - Offline replay and benchmarking
  - Integration with real-world capture files (Wireshark exports, tcpdump)

Two operation modes:
  1. PCAP → FlowRecord CSV  (extract_flows_from_pcap)
     Parses a PCAP/PCAPNG file using Scapy, reconstructs bidirectional
     TCP/UDP flows, and exports statistical features per flow.

  2. Labeled PCAP CSV → Training DataFrame  (load_pcap_csv)
     Loads a pre-labeled CSV that was exported by tools like CICFlowMeter,
     Wireshark's flow dissector, or the extract_flows_from_pcap() function.

Supported public datasets (PCAP-based):
  - CAIDA PCAP traces         — https://www.caida.org/catalog/datasets/
  - MAWI Working Group        — https://mawi.wide.ad.jp/mawi/
  - CTU-13 Botnet             — https://www.stratosphereips.org/datasets-ctu13
  - UNSW-NB15                 — https://research.unsw.edu.au/projects/unsw-nb15-dataset
  - CIC-IDS-2018              — https://www.unb.ca/cic/datasets/ids-2018.html

Feature set exported matches SentinelNet's FlowRecord schema:
    src_ip, dst_ip, src_port, dst_port, protocol,
    start_time, end_time, duration,
    fwd_packets, bwd_packets, fwd_bytes, bwd_bytes,
    syn_count, fin_count, rst_count, psh_count, ack_count,
    avg_fwd_iat, avg_bwd_iat,
    bytes_per_sec, packets_per_sec,
    flag_ratio, payload_entropy

Usage
-----
    from sentinelnet.data.pcap_loader import extract_flows_from_pcap, load_pcap_csv

    # Extract flows from a raw PCAP (requires scapy)
    df = extract_flows_from_pcap(
        pcap_path="/data/capture.pcap",
        label="NORMAL",          # or None for unlabeled
        max_packets=500_000,
    )
    df.to_csv("flows.csv", index=False)

    # Load a pre-labeled CICFlowMeter CSV
    df = load_pcap_csv("/data/cicflowmeter_output.csv", format="cicflowmeter")
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Flow-level feature set (matches SentinelNet internal FlowRecord schema)
# ---------------------------------------------------------------------------

PCAP_FLOW_FEATURES = [
    "duration",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "bytes_per_sec",
    "packets_per_sec",
    "avg_fwd_iat",
    "avg_bwd_iat",
    "syn_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "ack_count",
    "flag_ratio",
    "payload_entropy",
    "unique_dst_ports",
]

# ---------------------------------------------------------------------------
# Internal flow accumulator
# ---------------------------------------------------------------------------


@dataclass
class _FlowAccumulator:
    """Accumulates packet-level data for a single bidirectional flow."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP

    start_time: float = 0.0
    last_time: float = 0.0

    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    # TCP flags
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0

    fwd_iats: List[float] = field(default_factory=list)
    bwd_iats: List[float] = field(default_factory=list)
    _last_fwd_time: float = 0.0
    _last_bwd_time: float = 0.0

    dst_ports_seen: set = field(default_factory=set)
    payload_bytes: bytearray = field(default_factory=bytearray)

    def add_packet(
        self,
        timestamp: float,
        payload_len: int,
        is_forward: bool,
        flags: int = 0,
        raw_payload: bytes = b"",
    ) -> None:
        if self.start_time == 0.0:
            self.start_time = timestamp

        self.last_time = timestamp

        if is_forward:
            if self._last_fwd_time > 0:
                self.fwd_iats.append(timestamp - self._last_fwd_time)
            self._last_fwd_time = timestamp
            self.fwd_packets += 1
            self.fwd_bytes += payload_len
        else:
            if self._last_bwd_time > 0:
                self.bwd_iats.append(timestamp - self._last_bwd_time)
            self._last_bwd_time = timestamp
            self.bwd_packets += 1
            self.bwd_bytes += payload_len

        # TCP flags (bit positions: FIN=0, SYN=1, RST=2, PSH=3, ACK=4)
        if flags:
            if flags & 0x02:
                self.syn_count += 1
            if flags & 0x01:
                self.fin_count += 1
            if flags & 0x04:
                self.rst_count += 1
            if flags & 0x08:
                self.psh_count += 1
            if flags & 0x10:
                self.ack_count += 1

        self.dst_ports_seen.add(self.dst_port)

        # Keep up to 256 bytes of payload for entropy calculation
        if len(self.payload_bytes) < 256 and raw_payload:
            self.payload_bytes.extend(raw_payload[:256])

    def to_record(self, label: Optional[str] = None) -> dict:
        duration = max(self.last_time - self.start_time, 1e-6)
        total_bytes = self.fwd_bytes + self.bwd_bytes
        total_pkts = self.fwd_packets + self.bwd_packets
        total_flags = self.syn_count + self.fin_count + self.rst_count + self.psh_count + self.ack_count

        avg_fwd_iat = float(np.mean(self.fwd_iats)) if self.fwd_iats else 0.0
        avg_bwd_iat = float(np.mean(self.bwd_iats)) if self.bwd_iats else 0.0

        record = {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "duration": duration,
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            "bytes_per_sec": total_bytes / duration,
            "packets_per_sec": total_pkts / duration,
            "avg_fwd_iat": avg_fwd_iat * 1000,  # ms
            "avg_bwd_iat": avg_bwd_iat * 1000,
            "syn_count": self.syn_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "psh_count": self.psh_count,
            "ack_count": self.ack_count,
            "flag_ratio": total_flags / max(total_pkts, 1),
            "payload_entropy": _byte_entropy(bytes(self.payload_bytes)),
            "unique_dst_ports": len(self.dst_ports_seen),
        }
        if label is not None:
            record["label"] = label
        return record


# ---------------------------------------------------------------------------
# Entropy helper
# ---------------------------------------------------------------------------


def _byte_entropy(data: bytes) -> float:
    """Shannon entropy (bits per byte) of a byte string."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / len(data)
    return float(-np.sum(probs * np.log2(probs)))


# ---------------------------------------------------------------------------
# PCAP → Flow extraction
# ---------------------------------------------------------------------------


def extract_flows_from_pcap(
    pcap_path: Union[str, Path],
    label: Optional[str] = None,
    max_packets: int = 1_000_000,
    flow_timeout_sec: float = 120.0,
    output_csv: Optional[Union[str, Path]] = None,
) -> pd.DataFrame:
    """
    Parse a PCAP/PCAPNG file and extract bidirectional flow features.

    Requires scapy to be installed:
        pip install scapy

    Parameters
    ----------
    pcap_path : str or Path
        Path to the PCAP or PCAPNG file.
    label : str or None
        If provided, all extracted flows are tagged with this label.
    max_packets : int
        Stop processing after this many packets (for large captures).
    flow_timeout_sec : float
        Idle timeout — flows inactive for this long are closed.
    output_csv : str or Path or None
        If provided, save the DataFrame to this CSV path.

    Returns
    -------
    pd.DataFrame with PCAP_FLOW_FEATURES columns + optional 'label'.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.utils import PcapReader
    except ImportError as exc:
        raise ImportError("scapy is required for PCAP parsing. Install with: pip install scapy") from exc

    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    logger.info("Extracting flows from %s (max=%d packets)", pcap_path, max_packets)

    flows: Dict[str, _FlowAccumulator] = {}
    completed_flows: List[dict] = []
    packet_count = 0

    def _flow_key(src_ip, dst_ip, src_port, dst_port, proto) -> str:
        # Canonical key: lexicographically smaller IP is always "forward"
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}/{proto}"
        return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}/{proto}"

    def _flush_expired(current_ts: float):
        expired = [k for k, f in flows.items() if (current_ts - f.last_time) > flow_timeout_sec]
        for k in expired:
            completed_flows.append(flows.pop(k).to_record(label))

    try:
        with PcapReader(str(pcap_path)) as reader:
            for pkt in reader:
                packet_count += 1
                if packet_count > max_packets:
                    logger.info("Reached max_packets limit (%d)", max_packets)
                    break

                # Periodically flush expired flows
                if packet_count % 10_000 == 0:
                    ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
                    _flush_expired(ts)
                    logger.debug("Packets processed: %d | Active flows: %d", packet_count, len(flows))

                # Extract IP layer
                ip_layer = None
                if pkt.haslayer(IP):
                    ip_layer = pkt[IP]
                elif pkt.haslayer(IPv6):
                    ip_layer = pkt[IPv6]
                else:
                    continue

                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)
                timestamp = float(pkt.time)
                flags = 0
                raw_payload = b""

                if pkt.haslayer(TCP):
                    transport = pkt[TCP]
                    src_port = int(transport.sport)
                    dst_port = int(transport.dport)
                    flags = int(transport.flags)
                    proto = 6
                    raw_payload = bytes(transport.payload)[:256]
                elif pkt.haslayer(UDP):
                    transport = pkt[UDP]
                    src_port = int(transport.sport)
                    dst_port = int(transport.dport)
                    proto = 17
                    raw_payload = bytes(transport.payload)[:256]
                else:
                    continue

                payload_len = len(pkt) - (len(ip_layer) - len(ip_layer.payload))
                payload_len = max(0, payload_len)

                key = _flow_key(src_ip, dst_ip, src_port, dst_port, proto)
                is_forward = (src_ip, src_port) <= (dst_ip, dst_port)

                if key not in flows:
                    flows[key] = _FlowAccumulator(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=proto,
                    )

                flows[key].add_packet(
                    timestamp=timestamp,
                    payload_len=payload_len,
                    is_forward=is_forward,
                    flags=flags,
                    raw_payload=raw_payload,
                )

                # Close TCP flows on FIN/RST
                if proto == 6 and (flags & 0x01 or flags & 0x04):
                    completed_flows.append(flows.pop(key).to_record(label))

    except Exception as exc:
        logger.error("Error reading PCAP: %s", exc)
        raise

    # Flush remaining flows
    for flow in flows.values():
        completed_flows.append(flow.to_record(label))

    if not completed_flows:
        logger.warning("No flows extracted from %s", pcap_path)
        return pd.DataFrame(columns=PCAP_FLOW_FEATURES)

    df = pd.DataFrame(completed_flows)
    # Ensure all feature columns exist
    for feat in PCAP_FLOW_FEATURES:
        if feat not in df.columns:
            df[feat] = 0.0

    logger.info(
        "Extracted %d flows from %d packets | avg_duration=%.2fs",
        len(df),
        packet_count,
        df["duration"].mean(),
    )

    if output_csv:
        output_csv = Path(output_csv)
        output_csv.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_csv, index=False)
        logger.info("Flows saved to %s", output_csv)

    return df


# ---------------------------------------------------------------------------
# Load pre-labeled PCAP CSV (CICFlowMeter or custom)
# ---------------------------------------------------------------------------


def load_pcap_csv(
    csv_path: Union[str, Path],
    format: str = "auto",
    label_col: str = "label",
    sample_frac: float = 1.0,
    seed: int = 42,
) -> pd.DataFrame:
    """
    Load a pre-labeled flow CSV generated by CICFlowMeter, Wireshark, or
    SentinelNet's own extract_flows_from_pcap().

    Parameters
    ----------
    csv_path : str or Path
    format : "auto" | "cicflowmeter" | "sentinelnet"
        - "cicflowmeter": CICFlowMeter column naming convention
        - "sentinelnet":  extract_flows_from_pcap() output
        - "auto":         auto-detect by inspecting headers
    label_col : str
        Name of the label column (default "label").
    sample_frac : float
        Fraction of rows to sample.
    seed : int

    Returns
    -------
    pd.DataFrame with PCAP_FLOW_FEATURES + 'label' columns.
    """
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = [c.strip().lower() for c in df.columns]

    # Auto-detect format
    if format == "auto":
        if "flow duration" in df.columns or "flow bytes/s" in df.columns:
            format = "cicflowmeter"
        else:
            format = "sentinelnet"
        logger.info("Auto-detected format: %s", format)

    if format == "cicflowmeter":
        df = _normalise_cicflowmeter(df, label_col)
    else:
        # Already in sentinelnet format — just ensure columns exist
        for feat in PCAP_FLOW_FEATURES:
            if feat not in df.columns:
                df[feat] = 0.0

    if label_col in df.columns:
        df["label"] = df[label_col]

    if sample_frac < 1.0:
        df = df.sample(frac=sample_frac, random_state=seed).reset_index(drop=True)

    logger.info("Loaded %d flows from %s", len(df), csv_path)
    return df


# ---------------------------------------------------------------------------
# CICFlowMeter normaliser
# ---------------------------------------------------------------------------

_CICFLOWMETER_COL_MAP = {
    "flow duration": "duration",
    "total fwd packets": "fwd_packets",
    "total backward packets": "bwd_packets",
    "total length of fwd packets": "fwd_bytes",
    "total length of bwd packets": "bwd_bytes",
    "flow bytes/s": "bytes_per_sec",
    "flow packets/s": "packets_per_sec",
    "fwd iat mean": "avg_fwd_iat",
    "bwd iat mean": "avg_bwd_iat",
    "syn flag count": "syn_count",
    "fin flag count": "fin_count",
    "rst flag count": "rst_count",
    "psh flag count": "psh_count",
    "ack flag count": "ack_count",
}

# Label map: CICFlowMeter → SentinelNet canonical
_CICFLOWMETER_LABEL_MAP = {
    "benign": "NORMAL",
    "normal": "NORMAL",
    "dos hulk": "DoS",
    "dos goldeneye": "DoS",
    "dos slowloris": "DoS",
    "ddos": "DoS",
    "portscan": "PortScan",
    "ftp-patator": "BruteForce",
    "ssh-patator": "BruteForce",
    "brute force": "BruteForce",
    "infiltration": "DataExfil",
    "botnet": "DataExfil",
}


def _normalise_cicflowmeter(df: pd.DataFrame, label_col: str) -> pd.DataFrame:
    out = pd.DataFrame()
    for raw_col, feat_name in _CICFLOWMETER_COL_MAP.items():
        if raw_col in df.columns and feat_name not in out.columns:
            out[feat_name] = pd.to_numeric(df[raw_col], errors="coerce").fillna(0.0)

    # Derive flag_ratio
    flag_cols = ["syn_count", "fin_count", "rst_count", "psh_count", "ack_count"]
    if all(c in out.columns for c in flag_cols):
        total_flags = sum(out[c] for c in flag_cols)
        total_pkts = out.get("fwd_packets", pd.Series(1)) + out.get("bwd_packets", pd.Series(1))
        out["flag_ratio"] = total_flags / total_pkts.clip(lower=1)
    else:
        out["flag_ratio"] = 0.0

    # Entropy not in CICFlowMeter — proxy via bytes/packets ratio
    out["payload_entropy"] = 0.0
    out["unique_dst_ports"] = 1

    # Fill missing
    for feat in PCAP_FLOW_FEATURES:
        if feat not in out.columns:
            out[feat] = 0.0

    # Labels
    if label_col in df.columns:
        raw_labels = df[label_col].astype(str).str.strip().str.lower()
        out["label"] = raw_labels.map(lambda x: _CICFLOWMETER_LABEL_MAP.get(x, "DataExfil"))

    # Drop Inf/NaN
    out.replace([np.inf, -np.inf], np.nan, inplace=True)
    out.fillna(0.0, inplace=True)

    return out


# ---------------------------------------------------------------------------
# Batch PCAP directory loader
# ---------------------------------------------------------------------------


def load_pcap_directory(
    directory: Union[str, Path],
    label_map: Optional[Dict[str, str]] = None,
    output_csv: Optional[Union[str, Path]] = None,
    max_packets_per_file: int = 500_000,
) -> pd.DataFrame:
    """
    Recursively find all PCAP/PCAPNG files in a directory and extract flows.

    Parameters
    ----------
    directory : str or Path
        Root directory to search.
    label_map : dict or None
        Maps filename pattern → label string.
        Example: {"normal": "NORMAL", "dos": "DoS", "scan": "PortScan"}
        If None, all flows are unlabeled.
    output_csv : str or Path or None
        If provided, save combined DataFrame.
    max_packets_per_file : int

    Returns
    -------
    pd.DataFrame
    """
    directory = Path(directory)
    pcap_files = list(directory.rglob("*.pcap")) + list(directory.rglob("*.pcapng"))

    if not pcap_files:
        raise FileNotFoundError(f"No PCAP files found in {directory}")

    logger.info("Found %d PCAP files in %s", len(pcap_files), directory)
    all_dfs = []

    for pcap_file in pcap_files:
        # Determine label from filename
        label = None
        if label_map:
            fname_lower = pcap_file.name.lower()
            for pattern, mapped_label in label_map.items():
                if pattern.lower() in fname_lower:
                    label = mapped_label
                    break

        try:
            df = extract_flows_from_pcap(
                pcap_path=pcap_file,
                label=label,
                max_packets=max_packets_per_file,
            )
            df["source_file"] = pcap_file.name
            all_dfs.append(df)
        except Exception as exc:
            logger.error("Failed to process %s: %s", pcap_file, exc)
            continue

    if not all_dfs:
        return pd.DataFrame(columns=PCAP_FLOW_FEATURES)

    combined = pd.concat(all_dfs, ignore_index=True)
    logger.info("Combined dataset: %d flows from %d files", len(combined), len(all_dfs))

    if output_csv:
        output_csv = Path(output_csv)
        output_csv.parent.mkdir(parents=True, exist_ok=True)
        combined.to_csv(output_csv, index=False)
        logger.info("Combined flows saved to %s", output_csv)

    return combined
