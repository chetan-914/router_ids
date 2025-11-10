"""Tests for CoreManager."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from router_ids.core import CoreManager
from router_ids.features.pcap_parser import parse_pcap


class TestCoreManager:
    """Test CoreManager functionality."""

    def test_initialization(self):
        """Test CoreManager initialization."""
        manager = CoreManager()
        assert manager is not None
        assert len(manager.detectors) > 0

    def test_detector_registration(self):
        """Test custom detector registration."""
        from router_ids.features.base import FeatureExtractor
        from typing import Any, Dict, List

        class DummyExtractor(FeatureExtractor):
            def extract(self, packets: List[Any]) -> Dict[str, Any]:
                return {"dummy_feature": 1.0}

        manager = CoreManager()
        initial_count = len(manager.detectors)
        
        manager.register_detector("dummy", DummyExtractor())
        
        assert len(manager.detectors) == initial_count + 1
        assert "dummy" in manager.detectors

    def test_run_once_no_packets(self):
        """Test CoreManager with empty pcap."""
        # This is a smoke test - just ensure it doesn't crash
        manager = CoreManager()
        
        # Generate a minimal pcap
        from scapy.all import wrpcap
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_pcap = f.name
        
        try:
            # Create empty pcap
            wrpcap(temp_pcap, [])
            
            results = manager.run_once(temp_pcap)
            
            assert "timestamp" in results
            assert "detections" in results
        
        finally:
            if os.path.exists(temp_pcap):
                os.remove(temp_pcap)

    def test_run_once_with_sample_traffic(self, sample_pcap_path):
        """Test CoreManager with sample traffic."""
        # First generate sample pcap
        from examples.sample_pcap_generator import generate_benign_traffic
        from scapy.all import wrpcap
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_pcap = f.name
        
        try:
            packets = generate_benign_traffic()
            wrpcap(temp_pcap, packets)
            
            manager = CoreManager()
            results = manager.run_once(temp_pcap)
            
            assert "timestamp" in results
            assert "detections" in results
            assert len(results["detections"]) > 0
        
        finally:
            if os.path.exists(temp_pcap):
                os.remove(temp_pcap)
