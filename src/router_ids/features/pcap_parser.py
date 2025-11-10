"""Utility for parsing pcap files using Scapy."""

import logging
from typing import List

from scapy.all import rdpcap
from scapy.packet import Packet

logger = logging.getLogger(__name__)


def parse_pcap(pcap_path: str) -> List[Packet]:
    """
    Parse a pcap file and return a list of packets.

    Args:
        pcap_path: Path to pcap file

    Returns:
        List of scapy Packet objects

    Raises:
        FileNotFoundError: If pcap file does not exist
        Exception: If pcap parsing fails
    """
    try:
        packets = rdpcap(pcap_path)
        logger.info(f"Parsed {len(packets)} packets from {pcap_path}")
        return packets
    except FileNotFoundError:
        logger.error(f"Pcap file not found: {pcap_path}")
        raise
    except Exception as e:
        logger.error(f"Error parsing pcap file {pcap_path}: {e}")
        raise
