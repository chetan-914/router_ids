"""Feature extractor for C2C (Command and Control) detection."""

import logging
from collections import Counter, defaultdict
from typing import Any, Dict, List

from scapy.layers.inet import IP, TCP, UDP

logger = logging.getLogger(__name__)


class C2CFeatureExtractor:
    """
    Extract C2C (Command & Control)-relevant features.

    C2C indicators:
    - Long-lived flows to same destination
    - Regular communication patterns (beaconing)
    - Unusual port usage
    - Data exfiltration patterns (small upload, large download)
    """

    def extract(self, packets: List[Any]) -> Dict[str, Any]:
        """Extract C2C-specific features."""
        if not packets:
            return self._empty_features()

        flows: Dict[tuple, dict] = defaultdict(
            lambda: {"packets": 0, "bytes": 0, "protocols": Counter()}
        )
        dst_ports: Counter = Counter()
        src_ports: Counter = Counter()

        for pkt in packets:
            try:
                if IP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    proto = pkt[IP].proto
                    pkt_len = len(pkt)

                    # Extract port information
                    src_port = 0
                    dst_port = 0

                    if TCP in pkt:
                        src_port = pkt[TCP].sport
                        dst_port = pkt[TCP].dport
                    elif UDP in pkt:
                        src_port = pkt[UDP].sport
                        dst_port = pkt[UDP].dport

                    # Track flows (src_ip, dst_ip, dst_port)
                    flow_key = (src_ip, dst_ip, dst_port)
                    flows[flow_key]["packets"] += 1
                    flows[flow_key]["bytes"] += pkt_len
                    flows[flow_key]["protocols"][proto] += 1

                    dst_ports[dst_port] += 1
                    src_ports[src_port] += 1

            except Exception as e:
                logger.debug(f"Error processing packet: {e}")
                continue

        num_packets = len(packets)
        num_flows = len(flows)

        # Calculate flow statistics
        flow_durations = (
            [flow["packets"] for flow in flows.values()] if flows else []
        )
        avg_flow_packets = (
            sum(flow_durations) / len(flow_durations)
            if flow_durations
            else 0
        )
        max_flow_packets = max(flow_durations) if flow_durations else 0

        # Unique destination ports
        unique_dst_ports = len(dst_ports)
        unique_src_ports = len(src_ports)

        # Identify long-lived flows (potential C2C beaconing)
        long_lived_flows = sum(
            1 for flow in flows.values() if flow["packets"] > 10
        )

        # Port-based anomalies
        # Non-standard ports (> 1024)
        non_standard_dst_ports = sum(
            1 for port in dst_ports.keys() if port > 1024
        )

        # Beaconing indicator: regular traffic to same destination
        # (flows with consistent packet counts)
        packet_counts = [flow["packets"] for flow in flows.values()]
        if packet_counts:
            avg_packets_per_flow = sum(packet_counts) / len(packet_counts)
            # High variance in packet counts might indicate regular beaconing
            variance = (
                sum(
                    (x - avg_packets_per_flow) ** 2 for x in packet_counts
                )
                / len(packet_counts)
            )
        else:
            variance = 0

        features = {
            "num_flows": num_flows,
            "average_flow_packets": avg_flow_packets,
            "max_flow_packets": max_flow_packets,
            "unique_dst_ports": unique_dst_ports,
            "unique_src_ports": unique_src_ports,
            "long_lived_flows": long_lived_flows,
            "non_standard_dst_ports": non_standard_dst_ports,
            "flow_packet_variance": variance,
        }

        return features

    def _empty_features(self) -> Dict[str, Any]:
        """Return zero-valued features."""
        return {
            "num_flows": 0,
            "average_flow_packets": 0.0,
            "max_flow_packets": 0,
            "unique_dst_ports": 0,
            "unique_src_ports": 0,
            "long_lived_flows": 0,
            "non_standard_dst_ports": 0,
            "flow_packet_variance": 0.0,
        }
