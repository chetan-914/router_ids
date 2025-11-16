"""
Core manager for coordinating packet parsing, feature extraction, and model execution.
"""

import datetime
import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Callable

import yaml

from .features.base import FeatureExtractor
from .features.pcap_parser import parse_pcap
from .models.model_runner import ModelRunner
from .utils.logger import setup_logger

logger = logging.getLogger(__name__)


class CoreManager:
    """
    Main orchestrator for intrusion detection.

    Can be used in two modes:
    1. Single Run: Process a pre-existing pcap file with `run_once()`.
    2. Continuous Monitoring: Actively capture and analyze traffic in a loop
       using `start_monitoring()`.
    """

    def __init__(
        self,
        rules_path: Optional[str] = None,
        thresholds_path: Optional[str] = None,
        models_dir: Optional[str] = None,
        interface: str = "eth0",
        capture_duration: int = 30,
        monitor_interval: int = 60,
    ):
        """
        Initialize CoreManager.

        Args:
            rules_path: Path to rules.yaml file.
            thresholds_path: Path to thresholds.yaml file.
            models_dir: Directory containing serialized models.
            interface: Default network interface for continuous monitoring.
            capture_duration: How many seconds to capture traffic for in each cycle.
            monitor_interval: How many seconds to wait between captures.
        """
        self.logger = setup_logger(__name__)

        # Configuration for continuous monitoring
        self.interface = interface
        self.capture_duration = capture_duration
        self.monitor_interval = monitor_interval
        self.pcap_file = "/tmp/router_ids_capture.pcap"

        # State for monitoring thread
        self._is_monitoring = False
        self._monitoring_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Default paths relative to this module
        base_dir = Path(__file__).parent.parent.parent
        self.rules_path = rules_path or str(base_dir / "rules" / "rules.yaml")
        self.thresholds_path = thresholds_path or str(base_dir / "rules" / "thresholds.yaml")
        self.models_dir = models_dir or str(base_dir / "src" / "router_ids" / "models" / "model_joblib")

        self.rules = self._load_yaml(self.rules_path)
        self.thresholds = self._load_yaml(self.thresholds_path)
        self.detectors: Dict[str, Tuple[FeatureExtractor, Optional[ModelRunner]]] = {}
        self._register_default_detectors()
        self.logger.info("CoreManager initialized")

    def start_monitoring(self, callback: Optional[Callable[[Dict], None]] = None) -> None:
        """
        Starts continuous network monitoring in a background thread.

        This will repeatedly capture traffic, run analysis, and execute a
        callback function with the results.

        Args:
            callback: A function to call with the results after each cycle.
                      If None, results will be logged.
        """
        if self._is_monitoring:
            self.logger.warning("Monitoring is already running.")
            return

        self.logger.info(f"Starting continuous monitoring on interface '{self.interface}'...")
        self._is_monitoring = True
        self._stop_event.clear()
        
        self._monitoring_thread = threading.Thread(
            target=self._monitoring_loop, args=(callback,), daemon=True
        )
        self._monitoring_thread.start()

    def stop_monitoring(self) -> None:
        """Stops the continuous network monitoring."""
        if not self._is_monitoring:
            self.logger.warning("Monitoring is not running.")
            return

        self.logger.info("Stopping continuous monitoring...")
        self._stop_event.set()
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=self.capture_duration + 5)
        
        self._is_monitoring = False
        self.logger.info("Monitoring stopped.")
        # Clean up the last pcap file
        if os.path.exists(self.pcap_file):
            os.remove(self.pcap_file)
            self.logger.debug(f"Cleaned up {self.pcap_file}")

    def _monitoring_loop(self, callback: Optional[Callable[[Dict], None]]) -> None:
        """The main loop for capturing and analyzing traffic."""
        while not self._stop_event.is_set():
            self.logger.info(f"Starting new capture cycle for {self.capture_duration}s.")
            
            # Step 1: Capture traffic
            capture_success = self._capture_traffic(self.pcap_file)
            
            if capture_success:
                # Step 2: Run detection
                self.logger.info("Capture complete. Running detection...")
                results = self.run_once(self.pcap_file)
                
                # Step 3: Handle results via callback
                if callback:
                    try:
                        callback(results)
                    except Exception as e:
                        self.logger.error(f"Error in results callback: {e}")
                else:
                    self.logger.info(f"Detection results: {results}")
            else:
                self.logger.error("Traffic capture failed. Will retry after interval.")

            # Step 4: Wait for the next cycle
            self.logger.info(f"Cycle complete. Waiting for {self.monitor_interval}s.")
            self._stop_event.wait(self.monitor_interval)

    def _capture_traffic(self, output_file: str) -> bool:
        """
        Captures network traffic using tcpdump, wrapped by the timeout command
        for robust termination.
        """
        try:
            # We use the 'timeout' utility to ensure tcpdump stops cleanly.
            cmd = [
                "timeout",
                str(self.capture_duration),
                "tcpdump",
                "-i", self.interface,
                "-U",  # Use packet-buffering to ensure data is written
                "-w", output_file,
            ]
            self.logger.debug(f"Executing command: {' '.join(cmd)}")

            # The subprocess timeout is a failsafe, slightly longer than the command's timeout
            result = subprocess.run(
                cmd, timeout=self.capture_duration + 5,
                capture_output=True, text=True
            )

            # A return code of 124 from 'timeout' means it successfully timed out and stopped the command.
            # A return code of 0 means tcpdump finished before the timeout. Both are success cases for us.
            if result.returncode == 0 or result.returncode == 124:
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    return True
                else:
                    self.logger.error(f"tcpdump exited cleanly, but the output file '{output_file}' is empty or missing.")
                    self.logger.error(f"tcpdump stderr: {result.stderr}")
                    return False
            else:
                self.logger.error(f"Command failed with return code {result.returncode}: {result.stderr}")
                return False

        except FileNotFoundError:
            self.logger.error("`tcpdump` or `timeout` command not found. Please ensure both are installed and in your PATH.")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error("The subprocess monitor itself timed out. This should not happen.")
            return False
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during traffic capture: {e}")
            return False

    def _load_yaml(self, path: str) -> Dict[str, Any]:
        """Load YAML configuration file."""
        if not os.path.exists(path):
            self.logger.warning(f"Configuration file not found: {path}")
            return {}
        
        try:
            with open(path, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            self.logger.error(f"Error loading YAML from {path}: {e}")
            return {}

    def _register_default_detectors(self) -> None:
        """Register built-in detectors for DDoS, MITM, and C2C."""
        from .features.ddos_extractor import DDoSFeatureExtractor
        from .features.mitm_extractor import MITMFeatureExtractor
        from .features.c2c_extractor import C2CFeatureExtractor
        from .models.ddos_model import DDoSModelRunner
        from .models.mitm_model import MITMModelRunner
        from .models.c2c_model import C2CModelRunner

        # --- Register DDoS Detector ---
        ddos_extractor = DDoSFeatureExtractor()
        ddos_model_file = os.path.join(self.models_dir, "ddos_model.joblib")
        ddos_runner = None
        if os.path.exists(ddos_model_file):
            try:
                ddos_runner = DDoSModelRunner(ddos_model_file)
            except Exception as e:
                self.logger.warning(f"Failed to load DDoS model runner: {e}")
        else:
            self.logger.warning("DDoS model file not found. DDoS model detection will be disabled.")
        self.detectors["ddos"] = (ddos_extractor, ddos_runner)
        self.logger.info("Registered detector: ddos")

        # --- Register MITM Detector ---
        mitm_extractor = MITMFeatureExtractor()
        mitm_model_file = os.path.join(self.models_dir, "mitm_model.joblib")
        mitm_scaler_file = os.path.join(self.models_dir, "mitm_scaler.joblib")
        mitm_runner = None
        if os.path.exists(mitm_model_file) and os.path.exists(mitm_scaler_file):
            try:
                mitm_runner = MITMModelRunner(mitm_model_file, mitm_scaler_file)
            except Exception as e:
                self.logger.warning(f"Failed to load custom MITM model runner: {e}")
        else:
            self.logger.warning("MITM model or scaler file not found. MITM model detection will be disabled.")
        self.detectors["mitm"] = (mitm_extractor, mitm_runner)
        self.logger.info("Registered detector: mitm")
        
        # --- Register C2C Detector ---
        c2c_extractor = C2CFeatureExtractor()
        c2c_model_file = os.path.join(self.models_dir, "c2c_detection_model.joblib")
        c2c_scaler_file = os.path.join(self.models_dir, "c2_scaler.joblib")
        c2c_encoder_file = os.path.join(self.models_dir, "c2_encoder.joblib")
        
        c2c_runner = None
        if all(os.path.exists(f) for f in [c2c_model_file, c2c_scaler_file, c2c_encoder_file]):
            try:
                # Get prediction threshold from thresholds config
                threshold = self.thresholds.get("c2c", {}).get("prediction_threshold", 0.5)
                c2c_runner = C2CModelRunner(
                    c2c_model_file, c2c_scaler_file, c2c_encoder_file, threshold
                )
            except Exception as e:
                self.logger.warning(f"Failed to load C2C model runner: {e}")
        else:
            self.logger.warning("One or more C2C model files not found. C2C detection will be disabled.")
        
        self.detectors["c2c"] = (c2c_extractor, c2c_runner)
        self.logger.info("Registered detector: c2c")

    def register_detector(
        self,
        name: str,
        feature_extractor: FeatureExtractor,
        model_runner: Optional[ModelRunner] = None,
    ) -> None:
        """
        Register a custom detector.

        Args:
            name: Detector identifier (must match a key in rules.yaml)
            feature_extractor: Instance of FeatureExtractor subclass
            model_runner: Optional ModelRunner for predictions
        """
        self.detectors[name] = (feature_extractor, model_runner)
        self.logger.info(f"Registered custom detector: {name}")

    def _check_pre_rules(self, detector_name: str, features: Dict[str, Any]) -> bool:
        """
        Check if rule-based pre-checks pass for a detector.

        Args:
            detector_name: Name of detector to check
            features: Extracted features dictionary

        Returns:
            True if pre-checks pass (run model), False otherwise
        """
        if detector_name not in self.rules:
            return True

        detector_rules = self.rules[detector_name]
        if not detector_rules.get("pre_check_enabled", True):
            return True

        if detector_name not in self.thresholds:
            # If no thresholds are defined for this detector, assume pre-checks pass
            return True

        thresholds = self.thresholds[detector_name]

        # --- DDoS Pre-Checks ---
        if detector_name == "ddos":
            # NOTE: These feature names are from the original project's DDoS extractor
            packet_rate = features.get("packet_rate", 0)
            if packet_rate > thresholds.get("packet_rate_threshold", 10000):
                self.logger.debug(
                    f"DDoS pre-check passed: packet_rate={packet_rate}"
                )
                return True
            unique_srcs = features.get("unique_src_ips", 0)
            if unique_srcs > thresholds.get("unique_src_ips_threshold", 1000):
                self.logger.debug(
                    f"DDoS pre-check passed: unique_srcs={unique_srcs}"
                )
                return True
            return False

        # --- Custom MITM Pre-Checks ---
        elif detector_name == "mitm":
            mismatch_count = features.get("mac_ip_inconsistency", 0)
            if mismatch_count >= thresholds.get("min_mismatch_count", 1):
                self.logger.debug(f"MITM pre-check passed: mismatch_count={mismatch_count}")
                return True
            
            rate = features.get("packet_rate", 0)
            if rate >= thresholds.get("min_packet_rate", 0.005):
                self.logger.debug(f"MITM pre-check passed: packet_rate={rate}")
                return True
            
            return False

        # --- C2C Pre-Checks ---
        elif detector_name == "c2c":
            avg_duration = features.get("average_flow_duration", 0)
            if avg_duration > thresholds.get("average_flow_duration_threshold", 3600):
                self.logger.debug(
                    f"C2C pre-check passed: avg_duration={avg_duration}"
                )
                return True
            unique_ports = features.get("unique_dst_ports", 0)
            if unique_ports > thresholds.get("unique_dst_ports_threshold", 100):
                self.logger.debug(
                    f"C2C pre-check passed: unique_ports={unique_ports}"
                )
                return True
            return False

        return True

    def run_once(self, pcap_path: str) -> Dict[str, Any]:
        """
        Process a single pcap file and run detection models.

        Args:
            pcap_path: Path to pcap file (e.g., from tcpdump)

        Returns:
            Dictionary with structure:
            {
                'timestamp': ISO timestamp,
                'pcap_file': filename,
                'detections': {
                    'ddos': {'detected': bool, 'score': float, 'label': str, 'raw': dict},
                    'mitm': {...},
                    'c2c': {...},
                },
                'errors': [list of error messages],
            }
        """
        import datetime
        from .features.pcap_parser import parse_pcap

        results = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "pcap_file": os.path.basename(pcap_path),
            "detections": {},
            "errors": [],
        }

        # Step 1: Parse pcap and extract basic features (once per interval)
        try:
            packets = parse_pcap(pcap_path)
            self.logger.info(
                f"Parsed pcap file: {pcap_path}, packets: {len(packets)}"
            )
        except Exception as e:
            msg = f"Error parsing pcap file: {e}"
            self.logger.error(msg)
            results["errors"].append(msg)
            return results

        detector_features = {}
        for detector_name, (extractor, _) in self.detectors.items():
            try:
                features = extractor.extract(packets)
                detector_features[detector_name] = features
            except Exception as e:
                msg = f"Error extracting features for {detector_name}: {e}"
                self.logger.error(msg)
                results["errors"].append(msg)

        for detector_name, (_, model_runner) in self.detectors.items():
            try:
                features = detector_features.get(detector_name, {})
                if detector_name not in self.rules or not self.rules[detector_name].get("enabled", True):
                    continue

                if not self._check_pre_rules(detector_name, features):
                    results["detections"][detector_name] = {
                        "detected": False, "score": 0.0, "label": "benign",
                        "raw": features, "reason": "pre-check_failed",
                    }
                    continue

                if model_runner is None:
                    results["detections"][detector_name] = {
                        "detected": False, "score": 0.0, "label": "benign",
                        "raw": features, "reason": "model_not_available",
                    }
                    continue

                prediction = model_runner.predict(features)
                results["detections"][detector_name] = prediction
            except Exception as e:
                msg = f"Error running detector {detector_name}: {e}"
                self.logger.error(msg)
                results["errors"].append(msg)
                results["detections"][detector_name] = {
                    "detected": False, "score": 0.0, "label": "error",
                    "raw": {}, "reason": str(e),
                }

        return results
    