"""Feature extractor for MITM (Man-in-the-Middle) detection."""

import logging
from collections import Counter
from typing import Any, Dict, List, Tuple

from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether

logger = logging.getLogger(__name__)


class MITMFeatureExtractor:
    """
    Extract MITM-relevant features.

    MITM indicators:
    - ARP spoofing: Multiple MACs claiming same IP
    - Unusual ARP patterns: High ratio of ARP requests
    - MAC flapping: Frequent MAC address changes
    - Gratuitous ARP activity
    """

    def extract(self, packets: List[Any]) -> Dict[str, Any]:
        """Extract MITM-specific features."""
        if not packets:
            return self._empty_features()

        arp_requests = 0
        arp_replies = 0
        arp_gratuitous = 0
        mac_ip_pairs: Dict[str, set] = {}  # IP -> set of MACs
        ip_mac_pairs: Dict[str, set] = {}  # MAC -> set of IPs
        arp_src_ips: Counter = Counter()
        
        for pkt in packets:
            try:
                # Track ARP layer
                if ARP in pkt:
                    if pkt[ARP].op == 1:  # ARP Request
                        arp_requests += 1
                        arp_src_ips[pkt[ARP].psrc] += 1
                        # Gratuitous ARP: sender IP == target IP
                        if pkt[ARP].psrc == pkt[ARP].pdst:
                            arp_gratuitous += 1
                    elif pkt[ARP].op == 2:  # ARP Reply
                        arp_replies += 1
                        arp_src_ips[pkt[ARP].psrc] += 1

                    # Track MAC-IP associations
                    src_mac = pkt[ARP].hwsrc
                    src_ip = pkt[ARP].psrc
                    
                    if src_ip not in mac_ip_pairs:
                        mac_ip_pairs[src_ip] = set()
                    mac_ip_pairs[src_ip].add(src_mac)
                    
                    if src_mac not in ip_mac_pairs:
                        ip_mac_pairs[src_mac] = set()
                    ip_mac_pairs[src_mac].add(src_ip)

                # Also track Ethernet + IP combinations
                if Ether in pkt and IP in pkt:
                    eth_src = pkt[Ether].src
                    ip_src = pkt[IP].src
                    
                    if ip_src not in mac_ip_pairs:
                        mac_ip_pairs[ip_src] = set()
                    mac_ip_pairs[ip_src].add(eth_src)

            except Exception as e:
                logger.debug(f"Error processing packet: {e}")
                continue

        num_packets = len(packets)
        arp_total = arp_requests + arp_replies

        # Calculate MITM indicators
        arp_request_ratio = (
            arp_requests / arp_total if arp_total > 0 else 0
        )

        # MAC-IP mismatch count: IPs with multiple MACs
        mac_ip_mismatch_count = sum(
            1 for macs in mac_ip_pairs.values() if len(macs) > 1
        )

        # IP-MAC mismatch count: MACs with multiple IPs
        ip_mac_mismatch_count = sum(
            1 for ips in ip_mac_pairs.values() if len(ips) > 1
        )

        # Gratuitous ARP ratio
        gratuitous_ratio = (
            arp_gratuitous / arp_total if arp_total > 0 else 0
        )

        features = {
            "arp_requests": arp_requests,
            "arp_replies": arp_replies,
            "arp_gratuitous": arp_gratuitous,
            "arp_request_ratio": arp_request_ratio,
            "arp_total": arp_total,
            "mac_ip_mismatch_count": mac_ip_mismatch_count,
            "ip_mac_mismatch_count": ip_mac_mismatch_count,
            "gratuitous_ratio": gratuitous_ratio,
            "unique_arp_sources": len(arp_src_ips),
        }

        return features

    def _empty_features(self) -> Dict[str, Any]:
        """Return zero-valued features."""
        return {
            "arp_requests": 0,
            "arp_replies": 0,
            "arp_gratuitous": 0,
            "arp_request_ratio": 0.0,
            "arp_total": 0,
            "mac_ip_mismatch_count": 0,
            "ip_mac_mismatch_count": 0,
            "gratuitous_ratio": 0.0,
            "unique_arp_sources": 0,
        }
