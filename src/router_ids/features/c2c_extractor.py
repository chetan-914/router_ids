"""
Feature extractor for the C2C detection model.

This extractor identifies the most significant flow in a packet capture
and extracts connection-level features similar to those found in Zeek/Bro logs.
"""

import logging
from collections import defaultdict
from typing import Any, Dict, List

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

from .base import FeatureExtractor

logger = logging.getLogger(__name__)


def get_service(port: int, proto: str) -> str:
    """Infer service from well-known ports."""
    services = {
        80: "http", 443: "ssl", 53: "dns", 22: "ssh", 21: "ftp", 6667: "irc"
    }
    return services.get(port, "unknown")


class C2CFeatureExtractor(FeatureExtractor):
    """
    Extracts raw connection features for the C2C model.

    It finds the flow with the most packets and extracts features like
    duration, byte counts, packet counts, protocol, service, and inferred
    connection state and history from TCP flags.
    """

    def extract(self, packets: List[Packet]) -> Dict[str, Any]:
        """Find the dominant flow and extract its features."""
        if not packets:
            return self._empty_features()

        flows = self._group_packets_into_flows(packets)
        if not flows:
            return self._empty_features()

        # Find the most significant flow (by packet count)
        dominant_flow_key = max(flows, key=lambda k: len(flows[k]))
        dominant_flow_packets = flows[dominant_flow_key]

        # --- Feature Calculation for the Dominant Flow ---
        orig_ip, resp_ip, orig_port, resp_port, proto_num = dominant_flow_key
        proto = {6: "tcp", 17: "udp", 1: "icmp"}.get(proto_num, "unknown")
        service = get_service(resp_port, proto)
        
        first_pkt_time = dominant_flow_packets[0].time
        last_pkt_time = dominant_flow_packets[-1].time
        duration = float(last_pkt_time - first_pkt_time)

        orig_bytes, resp_bytes = 0, 0
        orig_pkts, resp_pkts = 0, 0
        
        # Infer connection state and history from TCP flags
        conn_state = "OTH"  # Default
        history = []
        seen_syn = False
        seen_synack = False
        seen_fin = False

        for pkt in dominant_flow_packets:
            is_orig = pkt[IP].src == orig_ip
            if is_orig:
                orig_pkts += 1
                orig_bytes += len(pkt)
            else:
                resp_pkts += 1
                resp_bytes += len(pkt)

            if TCP in pkt:
                flags = pkt[TCP].flags
                if flags == "S":
                    seen_syn = True
                    history.append("S")
                elif flags == "SA":
                    seen_synack = True
                    history.append("H") # History 'H' for SYN-ACK
                elif "F" in flags:
                    seen_fin = True
                    history.append("F")
                elif "R" in flags:
                    conn_state = "REJ" if seen_syn and not seen_synack else "RSTO"
                    history.append("R")
                elif "." in flags: # PSH+ACK
                    history.append("D") # 'D' for data
                elif "A" in flags:
                    history.append("A")


        # Infer final connection state
        if seen_syn and seen_synack and seen_fin:
            conn_state = "SF"
        elif seen_syn and not seen_synack:
            conn_state = "S0"
        elif seen_syn and seen_synack and not seen_fin:
            conn_state = "ESTABLISHED" # Not a standard Zeek state, but informative

        return {
            "proto": proto,
            "service": service,
            "duration": duration,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "conn_state": conn_state,
            "history": "".join(history)[:10], # Truncate history
            "orig_pkts": orig_pkts,
            "resp_pkts": resp_pkts,
        }

    def _group_packets_into_flows(self, packets: List[Packet]) -> Dict[tuple, List[Packet]]:
        """Groups packets into flows using a 5-tuple key."""
        flows = defaultdict(list)
        for pkt in packets:
            if IP not in pkt:
                continue
            
            proto = pkt[IP].proto
            sport, dport = 0, 0
            if TCP in pkt or UDP in pkt:
                sport = pkt.sport
                dport = pkt.dport

            # Consistent flow key (orig -> resp)
            if sport < dport:
                key = (pkt[IP].src, pkt[IP].dst, sport, dport, proto)
            else:
                key = (pkt[IP].dst, pkt[IP].src, dport, sport, proto)
            
            flows[key].append(pkt)
        return flows

    def _empty_features(self) -> Dict[str, Any]:
        """Return zero-valued features when no packets are provided."""
        return {
            "proto": "-", "service": "-", "duration": 0.0,
            "orig_bytes": 0, "resp_bytes": 0, "conn_state": "-",
            "history": "-", "orig_pkts": 0, "resp_pkts": 0,
        }