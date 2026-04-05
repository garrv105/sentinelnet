"""
SentinelNet CLI Entry Point
Usage: python -m sentinelnet [options]
"""

import argparse
import logging
import sys
import yaml
from pathlib import Path

from .core.engine import SentinelEngine


def setup_logging(level: str):
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=fmt,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("sentinelnet.log"),
        ],
    )


def load_config(path: str) -> dict:
    if not Path(path).exists():
        print(f"Config file not found: {path}. Using defaults.")
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def main():
    parser = argparse.ArgumentParser(
        description="SentinelNet - Adaptive Threat Detection & Response",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Monitor live interface:
    python -m sentinelnet --interface eth0

  Replay PCAP file:
    python -m sentinelnet --pcap capture.pcap

  Use config file:
    python -m sentinelnet --config sentinelnet.yaml

  Enable API server:
    python -m sentinelnet --interface eth0 --api --api-port 8000
        """,
    )
    parser.add_argument("--interface", "-i", help="Network interface to monitor")
    parser.add_argument("--pcap", "-r", help="PCAP file to replay")
    parser.add_argument("--config", "-c", default="sentinelnet.yaml", help="Config file path")
    parser.add_argument("--filter", "-f", default="", help="BPF filter expression")
    parser.add_argument("--api", action="store_true", help="Enable REST API server")
    parser.add_argument("--api-port", type=int, default=8000, help="API server port")
    parser.add_argument("--dry-run", action="store_true", help="Do not apply firewall rules")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    setup_logging(args.log_level)
    logger = logging.getLogger("sentinelnet.cli")

    config = load_config(args.config)

    # CLI args override config file
    if args.interface:
        config["interface"] = args.interface
    if args.pcap:
        config["pcap_file"] = args.pcap
    if args.filter:
        config["bpf_filter"] = args.filter
    if args.api:
        config["api_enabled"] = True
    if args.api_port:
        config["api_port"] = args.api_port
    if args.dry_run:
        config.setdefault("response", {})["dry_run"] = True

    if not config.get("interface") and not config.get("pcap_file"):
        print("\nERROR: Specify --interface or --pcap\n")
        parser.print_help()
        sys.exit(1)

    logger.info("Starting SentinelNet with config: %s", config)

    engine = SentinelEngine.from_config(config)
    engine.start()
    engine.wait()


if __name__ == "__main__":
    main()
