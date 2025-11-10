"""Basic feature extractor for common network statistics."""

import logging
from collections import Counter, defaultdict
from typing import Any, Dict, List, Set

from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from .base import FeatureExtractor

logger = logging.getLogger(__name__)


class BasicFeatureExtractor(FeatureExtractor):
    """
    Extract common network statistics from packets.

    Features include:
    - Packet counts and rates
    - Unique source/destination IPs and MACs
    - Protocol distribution
    - Flow-level statistics
    - ARP activity
    """

    def extract(self, packets: List[Any]) -> Dict[str, Any]:
        """
        Extract basic network features from packets.

        Args:
            packets: List of scapy Packet objects

        Returns:
            Dictionary with basic network statistics
        """
        if not packets:
            return self._empty_features()

        # Initialize counters
        src_ips: Set[str] = set()
        dst_ips: Set[str] = set()
        src_macs: Set[str] = set()
        dst_macs: Set[str] = set()
        src_ip_packets: Counter = Counter()
        dst_ip_packets: Counter = Counter()
        protocols: Counter = Counter()
        arp_requests = 0
        arp_replies = 0
        icmp_count = 0
        tcp_count = 0
        udp_count = 0
        flows: Dict[tuple, float] = {}  # (src_ip, dst_ip, dst_port) -> duration

        total_bytes = 0
        packet_sizes = []

        for pkt in packets:
            try:
                # Extract Ethernet layer (MAC addresses)
                if Ether in pkt:
                    src_macs.add(pkt[Ether].src)
                    dst_macs.add(pkt[Ether].dst)

                # Extract IP layer
                if IP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    src_ips.add(src_ip)
                    dst_ips.add(dst_ip)
                    src_ip_packets[src_ip] += 1
                    dst_ip_packets[dst_ip] += 1

                    # Track protocol
                    proto = pkt[IP].proto
                    if proto == 6:
                        tcp_count += 1
                        protocols["tcp"] += 1
                    elif proto == 17:
                        udp_count += 1
                        protocols["udp"] += 1
                    elif proto == 1:
                        icmp_count += 1
                        protocols["icmp"] += 1
                    else:
                        protocols[f"proto_{proto}"] += 1

                    # Track flows (simplified: src_ip, dst_ip, dst_port)
                    if hasattr(pkt[IP], "dst"):
                        if hasattr(pkt, "sport") or hasattr(pkt, "dport"):
                            dst_port = getattr(pkt, "dport", 0)
                            flow_key = (src_ip, dst_ip, dst_port)
                            if flow_key not in flows:
                                flows[flow_key] = 1.0
                            else:
                                flows[flow_key] += 1.0

                # Extract ARP layer
                if ARP in pkt:
                    if pkt[ARP].op == 1:  # ARP Request
                        arp_requests += 1
                    elif pkt[ARP].op == 2:  # ARP Reply
                        arp_replies += 1

                # Extract ICMP
                if ICMP in pkt:
                    icmp_count += 1

                # Track packet size
                packet_sizes.append(len(pkt))
                total_bytes += len(pkt)

            except Exception as e:
                logger.debug(f"Error processing packet: {e}")
                continue

        # Calculate aggregated features
        num_packets = len(packets)
        avg_packet_size = total_bytes / num_packets if num_packets > 0 else 0
        packet_rate = num_packets  # Packets per capture interval (interval is implicit)
        
        # Top source IP (% of traffic)
        top_src_ip = src_ip_packets.most_common(1) if src_ip_packets else 0
        top_src_ratio = top_src_ip / num_packets if num_packets > 0 else 0

        # Average flow duration (packets per flow as proxy)
        avg_flow_packets = sum(flows.values()) / len(flows) if flows else 0

        arp_total = arp_requests + arp_replies
        arp_request_ratio = (
            arp_requests / arp_total if arp_total > 0 else 0
        )

        features = {
            "total_packets": num_packets,
            "total_bytes": total_bytes,
            "average_packet_size": avg_packet_size,
            "packet_rate": packet_rate,
            "unique_src_ips": len(src_ips),
            "unique_dst_ips": len(dst_ips),
            "unique_src_macs": len(src_macs),
            "unique_dst_macs": len(dst_macs),
            "tcp_packets": tcp_count,
            "udp_packets": udp_count,
            "icmp_packets": icmp_count,
            "arp_requests": arp_requests,
            "arp_replies": arp_replies,
            "arp_request_ratio": arp_request_ratio,
            "arp_total": arp_total,
            "top_src_ip_ratio": top_src_ratio,
            "num_flows": len(flows),
            "average_flow_packets": avg_flow_packets,
        }

        return features

    def _empty_features(self) -> Dict[str, Any]:
        """Return zero-valued features when no packets are provided."""
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "average_packet_size": 0.0,
            "packet_rate": 0,
            "unique_src_ips": 0,
            "unique_dst_ips": 0,
            "unique_src_macs": 0,
            "unique_dst_macs": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "arp_requests": 0,
            "arp_replies": 0,
            "arp_request_ratio": 0.0,
            "arp_total": 0,
            "top_src_ip_ratio": 0.0,
            "num_flows": 0,
            "average_flow_packets": 0.0,
        }
