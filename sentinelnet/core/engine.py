"""
SentinelNet - Main Engine
===========================
Central orchestrator that wires together:
  PacketCaptureEngine → FlowTracker → RuleEngine + AnomalyDetector → EventBus → ResponseManager

Designed for CLI and programmatic usage.
"""

import logging
import queue
import threading
import time
from typing import Any, Dict, Optional

from ..detectors.anomaly_detector import AnomalyDetectionEngine
from ..detectors.rule_engine import RuleEngine
from ..responders.response_manager import ResponseManager
from .event_bus import EventBus
from .flow_tracker import FlowTracker
from .packet_capture import PacketCaptureEngine

logger = logging.getLogger(__name__)


class SentinelEngine:
    """
    Full detection + response pipeline.

    Usage:
        engine = SentinelEngine.from_config(config)
        engine.start()
        # ... runs until stopped
        engine.stop()
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        bpf_filter: str = "",
        response_config: Optional[Dict[str, Any]] = None,
        rules_path: Optional[str] = None,
        model_path: Optional[str] = None,
        anomaly_threshold: float = 0.75,
        flow_timeout: float = 120.0,
        api_enabled: bool = False,
        api_host: str = "0.0.0.0",
        api_port: int = 8000,
    ):
        self.api_enabled = api_enabled
        self.api_host = api_host
        self.api_port = api_port

        # Core components
        self.event_bus = EventBus()
        self.capture_engine = PacketCaptureEngine(
            interface=interface,
            pcap_file=pcap_file,
            bpf_filter=bpf_filter,
        )
        self.flow_tracker = FlowTracker(flow_timeout=flow_timeout)
        self.rule_engine = RuleEngine(bus=self.event_bus, config_path=rules_path)
        self.anomaly_engine = AnomalyDetectionEngine(
            bus=self.event_bus,
            anomaly_threshold=anomaly_threshold,
            model_path=model_path,
        )
        self.response_manager = ResponseManager(
            bus=self.event_bus,
            config=response_config or {},
        )

        self._running = False
        self._pipeline_thread: Optional[threading.Thread] = None
        self._flow_analysis_thread: Optional[threading.Thread] = None

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> "SentinelEngine":
        return cls(
            interface=config.get("interface"),
            pcap_file=config.get("pcap_file"),
            bpf_filter=config.get("bpf_filter", ""),
            response_config=config.get("response", {}),
            rules_path=config.get("rules_path"),
            model_path=config.get("model_path"),
            anomaly_threshold=config.get("anomaly_threshold", 0.75),
            flow_timeout=config.get("flow_timeout", 120.0),
            api_enabled=config.get("api_enabled", False),
            api_host=config.get("api_host", "0.0.0.0"),
            api_port=config.get("api_port", 8000),
        )

    def start(self):
        """Start all pipeline components."""
        logger.info("=" * 60)
        logger.info("SentinelNet Engine Starting")
        logger.info("=" * 60)
        self._running = True

        # Start capture
        self.capture_engine.start()

        # Start packet pipeline thread
        self._pipeline_thread = threading.Thread(
            target=self._packet_pipeline,
            name="packet-pipeline",
            daemon=True,
        )
        self._pipeline_thread.start()

        # Start flow analysis thread
        self._flow_analysis_thread = threading.Thread(
            target=self._flow_analysis_loop,
            name="flow-analysis",
            daemon=True,
        )
        self._flow_analysis_thread.start()

        # Start API server
        if self.api_enabled:
            self._start_api()

        logger.info("SentinelNet Engine running (Ctrl+C to stop)")

    def stop(self):
        """Gracefully stop all components."""
        logger.info("SentinelNet Engine stopping...")
        self._running = False
        self.capture_engine.stop()
        self.event_bus.shutdown()
        if self._pipeline_thread:
            self._pipeline_thread.join(timeout=5)
        if self._flow_analysis_thread:
            self._flow_analysis_thread.join(timeout=5)
        logger.info("SentinelNet Engine stopped.")

    def wait(self):
        """Block until the engine is stopped (for CLI usage)."""
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    # ------------------------------------------------------------------
    # Pipeline loops
    # ------------------------------------------------------------------

    def _packet_pipeline(self):
        """
        Reads parsed packets from the capture engine queue,
        updates the flow table, and runs rule-based detectors.
        """
        pkt_queue = self.capture_engine.packet_queue
        while self._running:
            try:
                pkt = pkt_queue.get(timeout=1.0)
                # Update flow table
                self.flow_tracker.update(pkt)
                # Rule-based detection on packet
                self.rule_engine.inspect_packet(pkt)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error("Pipeline error: %s", e)

    def _flow_analysis_loop(self):
        """
        Periodically retrieves completed flows from FlowTracker
        and runs anomaly detection + flow-level rules.
        """
        while self._running:
            time.sleep(5.0)
            try:
                flows = self.flow_tracker.get_completed_flows()
                for flow in flows:
                    self.rule_engine.inspect_flow(flow)
                    self.anomaly_engine.analyze_flow(flow)
            except Exception as e:
                logger.error("Flow analysis error: %s", e)

    def _start_api(self):
        """Start the FastAPI server in a background thread."""
        try:
            import uvicorn

            from ..api.server import create_app

            app = create_app(self)

            def run():
                uvicorn.run(
                    app,
                    host=self.api_host,
                    port=self.api_port,
                    log_level="warning",
                )

            t = threading.Thread(target=run, name="api-server", daemon=True)
            t.start()
            logger.info("API server started at http://%s:%d", self.api_host, self.api_port)
        except ImportError:
            logger.warning("uvicorn not installed. API server disabled.")
        except Exception as e:
            logger.error("Failed to start API server: %s", e)
