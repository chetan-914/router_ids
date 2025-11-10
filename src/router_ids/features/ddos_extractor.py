"""Feature extractor for DDoS detection."""

import logging
from collections import Counter
from typing import Any, Dict, List, Set

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from .base import FeatureExtractor

logger = logging.getLogger(__name__)


class DDoSFeatureExtractor(FeatureExtractor):
    """
    Extract DDoS-relevant features.

    DDoS indicators:
    - High packet rate
    - Many packets from few sources (amplification attacks)
    - High ratio of packets from single source
    - Unusual protocol distribution
    """

    def extract(self, packets: List[Any]) -> Dict[str, Any]:
        """Extract DDoS-specific features."""
        if not packets:
            return self._empty_features()

        src_ips: Counter = Counter()
        dst_ips: Counter = Counter()
        protocols: Counter = Counter()
        total_bytes = 0

        for pkt in packets:
            try:
                if IP in pkt:
                    src_ips[pkt[IP].src] += 1
                    dst_ips[pkt[IP].dst] += 1
                    total_bytes += len(pkt)
                    
                    proto = pkt[IP].proto
                    if proto == 6:
                        protocols["tcp"] += 1
                    elif proto == 17:
                        protocols["udp"] += 1
                    elif proto == 1:
                        protocols["icmp"] += 1
                    else:
                        protocols["other"] += 1
            except Exception as e:
                logger.debug(f"Error processing packet: {e}")
                continue

        num_packets = len(packets)
        
        # DDoS-specific features
        packet_rate = num_packets  # packets per interval
        unique_src_ips = len(src_ips)
        unique_dst_ips = len(dst_ips)
        
        # Top source IP ratio (high = potential source of attack or amplification)
        top_src_packets = src_ips.most_common(1) if src_ips else 0
        top_src_ratio = top_src_packets / num_packets if num_packets > 0 else 0
        
        # Top destination IP ratio (high = potential target)
        top_dst_packets = dst_ips.most_common(1) if dst_ips else 0
        top_dst_ratio = top_dst_packets / num_packets if num_packets > 0 else 0

        # Protocol ratio (high UDP/ICMP ratio may indicate reflection attacks)
        udp_count = protocols.get("udp", 0)
        icmp_count = protocols.get("icmp", 0)
        tcp_count = protocols.get("tcp", 0)
        
        udp_ratio = udp_count / num_packets if num_packets > 0 else 0
        icmp_ratio = icmp_count / num_packets if num_packets > 0 else 0
        
        avg_packet_size = total_bytes / num_packets if num_packets > 0 else 0

        features = {
            "packet_rate": packet_rate,
            "unique_src_ips": unique_src_ips,
            "unique_dst_ips": unique_dst_ips,
            "top_src_ratio": top_src_ratio,
            "top_dst_ratio": top_dst_ratio,
            "udp_ratio": udp_ratio,
            "icmp_ratio": icmp_ratio,
            "tcp_count": tcp_count,
            "avg_packet_size": avg_packet_size,
            "total_bytes": total_bytes,
        }

        return features

    def _empty_features(self) -> Dict[str, Any]:
        """Return zero-valued features."""
        return {
            "packet_rate": 0,
            "unique_src_ips": 0,
            "unique_dst_ips": 0,
            "top_src_ratio": 0.0,
            "top_dst_ratio": 0.0,
            "udp_ratio": 0.0,
            "icmp_ratio": 0.0,
            "tcp_count": 0,
            "avg_packet_size": 0.0,
            "total_bytes": 0,
        }
