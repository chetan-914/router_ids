import logging
from typing import Any, Dict, List

from scapy.layers.inet import IP, TCP, UDP

from .base import FeatureExtractor

logger = logging.getLogger(__name__)


class DDoSFeatureExtractor(FeatureExtractor):
    """
    Extracts features compatible with the custom DDoSDetector model.

    Features:
    - Packet_Size: Average size of packets.
    - Packets_Per_Sec: Rate of packets.
    - Flow_Duration: Duration of the capture window.
    - Bytes_Per_Sec: Rate of bytes.
    - Unique_IPs: Count of unique source IP addresses.
    - Port_Diversity: Count of unique destination ports.
    - TCP_Ratio: Ratio of TCP packets to total IP packets.
    - UDP_Ratio: Ratio of UDP packets to total IP packets.
    - SYN_Flag_Ratio: Ratio of TCP packets with only SYN flag set.
    - ACK_Flag_Ratio: Ratio of TCP packets with ACK flag set.
    """

    def extract(self, packets: List[Any]) -> Dict[str, Any]:
        """Extract DDoS-specific features from a list of scapy packets."""
        if not packets:
            return self._empty_features()

        # Calculate capture duration from packet timestamps
        try:
            first_pkt_time = packets[0].time
            last_pkt_time = packets[-1].time
            duration = float(last_pkt_time - first_pkt_time)
            if duration == 0:
                duration = 1.0  # Avoid division by zero for single-packet captures
        except (AttributeError, IndexError):
            duration = 1.0

        total_bytes = 0
        total_packets = len(packets)
        src_ips = set()
        dst_ports = set()
        tcp_count = 0
        udp_count = 0
        syn_count = 0
        ack_count = 0

        for pkt in packets:
            total_bytes += len(pkt)
            if IP in pkt:
                src_ips.add(pkt[IP].src)
                if TCP in pkt:
                    tcp_count += 1
                    dst_ports.add(pkt[TCP].dport)
                    # Check for pure SYN (S flag without A)
                    if 'S' in pkt[TCP].flags and 'A' not in pkt[TCP].flags:
                        syn_count += 1
                    # Check for ACK
                    if 'A' in pkt[TCP].flags:
                        ack_count += 1
                elif UDP in pkt:
                    udp_count += 1
                    dst_ports.add(pkt[UDP].dport)

        # --- Feature Calculations ---
        avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0
        packets_per_sec = total_packets / duration
        bytes_per_sec = total_bytes / duration
        unique_ips = len(src_ips)
        port_diversity = len(dst_ports)

        total_ip_packets = tcp_count + udp_count
        tcp_ratio = tcp_count / total_ip_packets if total_ip_packets > 0 else 0
        udp_ratio = udp_count / total_ip_packets if total_ip_packets > 0 else 0

        syn_flag_ratio = syn_count / tcp_count if tcp_count > 0 else 0
        ack_flag_ratio = ack_count / tcp_count if tcp_count > 0 else 0

        features = {
            'Packet_Size': avg_packet_size,
            'Packets_Per_Sec': packets_per_sec,
            'Flow_Duration': duration,
            'Bytes_Per_Sec': bytes_per_sec,
            'Unique_IPs': unique_ips,
            'Port_Diversity': port_diversity,
            'TCP_Ratio': tcp_ratio,
            'UDP_Ratio': udp_ratio,
            'SYN_Flag_Ratio': syn_flag_ratio,
            'ACK_Flag_Ratio': ack_flag_ratio,
        }

        return features

    def _empty_features(self) -> Dict[str, Any]:
        """Return zero-valued features for an empty packet list."""
        return {
            'Packet_Size': 0.0, 'Packets_Per_Sec': 0.0,
            'Flow_Duration': 0.0, 'Bytes_Per_Sec': 0.0,
            'Unique_IPs': 0, 'Port_Diversity': 0,
            'TCP_Ratio': 0.0, 'UDP_Ratio': 0.0,
            'SYN_Flag_Ratio': 0.0, 'ACK_Flag_Ratio': 0.0,
        }