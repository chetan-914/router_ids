"""Tests for feature extractors."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from router_ids.features.extractor import BasicFeatureExtractor
from router_ids.features.ddos_extractor import DDoSFeatureExtractor
from router_ids.features.mitm_extractor import MITMFeatureExtractor
from router_ids.features.c2c_extractor import C2CFeatureExtractor


class TestBasicFeatureExtractor:
    """Test BasicFeatureExtractor."""

    def test_extract_empty_packets(self):
        """Test feature extraction with empty packet list."""
        extractor = BasicFeatureExtractor()
        features = extractor.extract([])
        
        assert features["total_packets"] == 0
        assert features["unique_src_ips"] == 0
        assert features["unique_dst_ips"] == 0

    def test_extract_with_synthetic_traffic(self):
        """Test feature extraction with synthetic traffic."""
        from examples.sample_pcap_generator import generate_benign_traffic
        
        extractor = BasicFeatureExtractor()
        packets = generate_benign_traffic()
        features = extractor.extract(packets)
        
        assert features["total_packets"] > 0
        assert "unique_src_ips" in features
        assert "unique_dst_ips" in features
        assert "tcp_packets" in features
        assert "udp_packets" in features


class TestDDoSFeatureExtractor:
    """Test DDoSFeatureExtractor."""

    def test_extract_empty_packets(self):
        """Test DDoS feature extraction with empty packets."""
        extractor = DDoSFeatureExtractor()
        features = extractor.extract([])
        
        assert features["packet_rate"] == 0
        assert features["unique_src_ips"] == 0

    def test_extract_with_ddos_traffic(self):
        """Test DDoS feature extraction with attack traffic."""
        from examples.sample_pcap_generator import generate_ddos_traffic
        
        extractor = DDoSFeatureExtractor()
        packets = generate_ddos_traffic()
        features = extractor.extract(packets)
        
        assert features["packet_rate"] > 0
        assert features["unique_src_ips"] > 0
        assert "top_src_ratio" in features


class TestMITMFeatureExtractor:
    """Test MITMFeatureExtractor."""

    def test_extract_empty_packets(self):
        """Test MITM feature extraction with empty packets."""
        extractor = MITMFeatureExtractor()
        features = extractor.extract([])
        
        assert features["arp_requests"] == 0
        assert features["mac_ip_mismatch_count"] == 0

    def test_extract_with_mitm_traffic(self):
        """Test MITM feature extraction with attack traffic."""
        from examples.sample_pcap_generator import generate_mitm_traffic
        
        extractor = MITMFeatureExtractor()
        packets = generate_mitm_traffic()
        features = extractor.extract(packets)
        
        assert "arp_requests" in features
        assert "mac_ip_mismatch_count" in features


class TestC2CFeatureExtractor:
    """Test C2CFeatureExtractor."""

    def test_extract_empty_packets(self):
        """Test C2C feature extraction with empty packets."""
        extractor = C2CFeatureExtractor()
        features = extractor.extract([])
        
        assert features["num_flows"] == 0
        assert features["average_flow_packets"] == 0

    def test_extract_with_c2c_traffic(self):
        """Test C2C feature extraction with attack traffic."""
        from examples.sample_pcap_generator import generate_c2c_traffic
        
        extractor = C2CFeatureExtractor()
        packets = generate_c2c_traffic()
        features = extractor.extract(packets)
        
        assert features["num_flows"] > 0
        assert "average_flow_packets" in features
