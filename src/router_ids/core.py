"""
Core manager for coordinating packet parsing, feature extraction, and model execution.

Coordinates the detection pipeline:
1. Parse pcap file and extract packets
2. Run single-pass feature extraction (once per interval)
3. Check human-editable rules to decide which models to run
4. Execute selected models and aggregate results
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .features.base import FeatureExtractor
from .features.extractor import BasicFeatureExtractor
from .models.model_runner import ModelRunner
from .utils.logger import setup_logger

logger = logging.getLogger(__name__)


class CoreManager:
    """
    Main orchestrator for intrusion detection on a Raspberry Pi router.

    Accepts a pcap file captured by tcpdump, performs single-pass feature
    extraction, checks rules to decide which models to invoke, and returns
    structured detection results.
    """

    def __init__(
        self,
        rules_path: Optional[str] = None,
        thresholds_path: Optional[str] = None,
        models_dir: Optional[str] = None,
    ):
        """
        Initialize CoreManager.

        Args:
            rules_path: Path to rules.yaml file
            thresholds_path: Path to thresholds.yaml file
            models_dir: Directory containing serialized models
        """
        self.logger = setup_logger(__name__)
        
        # Default paths relative to this module
        base_dir = Path(__file__).parent.parent.parent
        self.rules_path = rules_path or str(base_dir / "rules" / "rules.yaml")
        self.thresholds_path = (
            thresholds_path or str(base_dir / "rules" / "thresholds.yaml")
        )
        self.models_dir = models_dir or str(base_dir / "src" / "router_ids" / "models")

        # Load configuration
        self.rules = self._load_yaml(self.rules_path)
        self.thresholds = self._load_yaml(self.thresholds_path)

        # Registry of detectors: {detector_name: (feature_extractor, model_runner)}
        self.detectors: Dict[str, Tuple[FeatureExtractor, Optional[ModelRunner]]] = {}

        # Register default detectors
        self._register_default_detectors()

        self.logger.info("CoreManager initialized")

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

        extractors = [
            ("ddos", DDoSFeatureExtractor()),
            ("mitm", MITMFeatureExtractor()),
            ("c2c", C2CFeatureExtractor()),
        ]

        for name, extractor in extractors:
            model_file = os.path.join(self.models_dir, f"{name}_model.joblib")
            try:
                runner = (
                    eval(f"{name.upper()}ModelRunner")(model_file)
                    if os.path.exists(model_file)
                    else None
                )
            except Exception as e:
                self.logger.warning(f"Failed to load model runner for {name}: {e}")
                runner = None

            self.detectors[name] = (extractor, runner)
            self.logger.info(f"Registered detector: {name}")

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
            return True

        thresholds = self.thresholds[detector_name]

        # Detector-specific rule checks
        if detector_name == "ddos":
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

        elif detector_name == "mitm":
            arp_ratio = features.get("arp_request_ratio", 0)
            if arp_ratio > thresholds.get("arp_request_ratio_threshold", 1.0):
                self.logger.debug(f"MITM pre-check passed: arp_ratio={arp_ratio}")
                return True
            mac_ip_mismatches = features.get("mac_ip_mismatch_count", 0)
            if (
                mac_ip_mismatches
                > thresholds.get("mac_ip_mismatch_threshold", 100)
            ):
                self.logger.debug(
                    f"MITM pre-check passed: mac_ip_mismatches={mac_ip_mismatches}"
                )
                return True
            return False

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

        # Step 2: Run feature extraction for each registered detector
        detector_features = {}
        for detector_name, (extractor, _) in self.detectors.items():
            try:
                features = extractor.extract(packets)
                detector_features[detector_name] = features
                self.logger.debug(f"{detector_name} features: {features}")
            except Exception as e:
                msg = f"Error extracting features for {detector_name}: {e}"
                self.logger.error(msg)
                results["errors"].append(msg)

        # Step 3: Check pre-check rules and invoke models
        for detector_name, (_, model_runner) in self.detectors.items():
            try:
                features = detector_features.get(detector_name, {})

                # Check if detector is enabled
                if detector_name not in self.rules:
                    self.logger.debug(f"Detector {detector_name} not in rules, skipping")
                    continue

                if not self.rules[detector_name].get("enabled", True):
                    self.logger.debug(f"Detector {detector_name} disabled, skipping")
                    continue

                # Check pre-check rules
                if not self._check_pre_rules(detector_name, features):
                    self.logger.debug(
                        f"Pre-checks failed for {detector_name}, skipping model"
                    )
                    results["detections"][detector_name] = {
                        "detected": False,
                        "score": 0.0,
                        "label": "benign",
                        "raw": features,
                        "reason": "pre-check_failed",
                    }
                    continue

                # Run model if pre-checks pass and model is available
                if model_runner is None:
                    self.logger.warning(
                        f"Model runner not available for {detector_name}"
                    )
                    results["detections"][detector_name] = {
                        "detected": False,
                        "score": 0.0,
                        "label": "benign",
                        "raw": features,
                        "reason": "model_not_available",
                    }
                    continue

                prediction = model_runner.predict(features)
                results["detections"][detector_name] = prediction
                self.logger.info(
                    f"{detector_name} detection: {prediction['detected']}, "
                    f"score: {prediction['score']}"
                )

            except Exception as e:
                msg = f"Error running detector {detector_name}: {e}"
                self.logger.error(msg)
                results["errors"].append(msg)
                results["detections"][detector_name] = {
                    "detected": False,
                    "score": 0.0,
                    "label": "error",
                    "raw": {},
                    "reason": str(e),
                }

        return results
