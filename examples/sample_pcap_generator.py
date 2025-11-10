"""
Generate sample pcap file with synthetic network traffic for testing.

Useful for testing the detection pipeline without relying on tcpdump.
"""

import sys
from pathlib import Path

from scapy.all import ARP, Ether, IP, ICMP, TCP, UDP, wrpcap
from scapy.packet import Packet

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def generate_benign_traffic() -> list:
    """Generate sample benign network traffic."""
    packets = []
    
    # Normal DNS queries (UDP port 53)
    for i in range(20):
        pkt = (
            Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
            / IP(src=f"192.168.1.{10+i}", dst="8.8.8.8")
            / UDP(sport=5000 + i, dport=53)
        )
        packets.append(pkt)
    
    # Normal HTTP traffic (TCP port 80)
    for i in range(20):
        pkt = (
            Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")
            / IP(src="192.168.1.100", dst=f"10.0.0.{1+i}")
            / TCP(sport=6000 + i, dport=80)
        )
        packets.append(pkt)
    
    # ARP traffic (normal)
    for i in range(10):
        pkt = (
            Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=1, hwsrc="00:11:22:33:44:55", psrc=f"192.168.1.{10+i}",
                  hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.1")
        )
        packets.append(pkt)
    
    return packets


def generate_ddos_traffic() -> list:
    """Generate sample DDoS attack traffic."""
    packets = []
    
    # Flood from many sources to one destination
    for i in range(500):
        pkt = (
            Ether(src=f"{i%255:02x}:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")
            / IP(src=f"10.{i//256}.{i%256}.1", dst="192.168.1.100")
            / UDP(sport=random_port(), dport=53)
        )
        packets.append(pkt)
    
    return packets


def generate_mitm_traffic() -> list:
    """Generate sample MITM attack traffic."""
    packets = []
    
    # Gratuitous ARP
    for i in range(30):
        pkt = (
            Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=2, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.1",
                  hwdst="00:11:22:33:44:55", pdst="192.168.1.1")
        )
        packets.append(pkt)
    
    # MAC-IP mismatches
    for i in range(20):
        pkt = (
            Ether(src=f"{i%255:02x}:bb:cc:dd:ee:ff", dst="aa:bb:cc:dd:ee:ff")
            / IP(src="192.168.1.100", dst="192.168.1.50")
            / TCP(sport=random_port(), dport=80)
        )
        packets.append(pkt)
    
    return packets


def generate_c2c_traffic() -> list:
    """Generate sample C2C communication traffic."""
    packets = []
    
    # Long-lived flows to same destination
    for i in range(100):
        pkt = (
            Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")
            / IP(src="192.168.1.100", dst="10.0.0.50")
            / TCP(sport=5555, dport=4444)
        )
        packets.append(pkt)
    
    # Periodic beacon-like traffic
    for i in range(50):
        pkt = (
            Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")
            / IP(src="192.168.1.100", dst=f"203.0.113.{10+i}")
            / TCP(sport=random_port(), dport=443)
        )
        packets.append(pkt)
    
    return packets


def random_port() -> int:
    """Generate random port number."""
    import random
    return random.randint(1024, 65535)


def main() -> None:
    """Generate sample pcap files."""
    import os
    
    output_dir = Path(__file__).parent
    
    # Generate benign traffic
    packets = generate_benign_traffic()
    wrpcap(str(output_dir / "sample_pcap.pcap"), packets)
    print(f"Generated benign sample pcap: {output_dir / 'sample_pcap.pcap'}")
    
    # Generate attack traffic (separate files for testing)
    packets = generate_ddos_traffic()
    wrpcap(str(output_dir / "sample_ddos.pcap"), packets)
    print(f"Generated DDoS sample pcap: {output_dir / 'sample_ddos.pcap'}")
    
    packets = generate_mitm_traffic()
    wrpcap(str(output_dir / "sample_mitm.pcap"), packets)
    print(f"Generated MITM sample pcap: {output_dir / 'sample_mitm.pcap'}")
    
    packets = generate_c2c_traffic()
    wrpcap(str(output_dir / "sample_c2c.pcap"), packets)
    print(f"Generated C2C sample pcap: {output_dir / 'sample_c2c.pcap'}")


if __name__ == "__main__":
    main()
