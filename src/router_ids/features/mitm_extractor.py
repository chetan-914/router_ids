"""
Feature extractor for the custom multi-class MITM model.
"""

import logging
from typing import Any, Dict, List

from scapy.layers.l2 import ARP, Ether

from .base import FeatureExtractor

logger = logging.getLogger(__name__)


class MITMFeatureExtractor(FeatureExtractor):
    """
    Extracts features compatible with the custom Random Forest MITM model.

    The 8 features are:
    - mac_ip_inconsistency: Count of IPs associated with more than one MAC address.
    - packet_in_count: Total number of packets in the capture window.
    - packet_rate: Packets per second.
    - rtt (avg): Average Round Trip Time. (NOTE: Placeholder, not implemented)
    - is_broadcast: 1 if broadcast packets are present, 0 otherwise.
    - arp_request: 1 if ARP requests are present, 0 otherwise.
    - arp_reply: 1 if ARP replies are present, 0 otherwise.
    - op_code(arp): Op-code of the first ARP packet found (1 for request, 2 for reply).
    """

    def extract(self, packets: List[Any]) -> Dict[str, Any]:
        """Extract MITM-specific features from a list of scapy packets."""
        if not packets:
            return self._empty_features()

        # --- Base Metrics ---
        packet_in_count = len(packets)
        try:
            duration = float(packets[-1].time - packets[0].time)
            if duration == 0: duration = 1.0
        except (AttributeError, IndexError):
            duration = 1.0
        packet_rate = packet_in_count / duration

        # --- Feature Extraction Loop ---
        mac_ip_pairs: Dict[str, set] = {}
        broadcast_count = 0
        arp_request_count = 0
        arp_reply_count = 0
        first_arp_opcode = 0

        for pkt in packets:
            # is_broadcast
            if Ether in pkt and pkt[Ether].dst == "ff:ff:ff:ff:ff:ff":
                broadcast_count += 1

            # ARP-related features
            if ARP in pkt:
                # op_code(arp) - capture the first one we see
                if first_arp_opcode == 0:
                    first_arp_opcode = pkt[ARP].op
                
                # arp_request / arp_reply
                if pkt[ARP].op == 1:
                    arp_request_count += 1
                elif pkt[ARP].op == 2:
                    arp_reply_count += 1

                # mac_ip_inconsistency
                src_mac = pkt[ARP].hwsrc
                src_ip = pkt[ARP].psrc
                if src_ip not in mac_ip_pairs:
                    mac_ip_pairs[src_ip] = set()
                mac_ip_pairs[src_ip].add(src_mac)

        # --- Final Feature Calculations ---
        mac_ip_inconsistency = sum(1 for macs in mac_ip_pairs.values() if len(macs) > 1)
        
        # NOTE: Calculating RTT from passive captures is complex and unreliable.
        # This is a placeholder as the model requires it. In a real scenario,
        # this would need a more sophisticated calculation (e.g., tracking TCP sequence numbers).
        rtt_avg = 0.0

        features = {
            'mac_ip_inconsistency': mac_ip_inconsistency,
            'packet_in_count': packet_in_count,
            'packet_rate': packet_rate,
            'rtt (avg)': rtt_avg,
            'is_broadcast': 1 if broadcast_count > 0 else 0,
            'arp_request': 1 if arp_request_count > 0 else 0,
            'arp_reply': 1 if arp_reply_count > 0 else 0,
            'op_code(arp)': first_arp_opcode,
        }
        return features

    def _empty_features(self) -> Dict[str, Any]:
        """Return zero-valued features for an empty packet list."""
        return {
            'mac_ip_inconsistency': 0, 'packet_in_count': 0,
            'packet_rate': 0.0, 'rtt (avg)': 0.0,
            'is_broadcast': 0, 'arp_request': 0,
            'arp_reply': 0, 'op_code(arp)': 0,
        }