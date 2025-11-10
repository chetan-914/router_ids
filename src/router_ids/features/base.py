"""Abstract base class for feature extractors."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List


class FeatureExtractor(ABC):
    """
    Abstract base class for all feature extractors.

    Subclasses must implement the extract() method to extract relevant
    features from a list of network packets.
    """

    @abstractmethod
    def extract(self, packets: List[Any]) -> Dict[str, Any]:
        """
        Extract features from a list of packets.

        Args:
            packets: List of scapy Packet objects

        Returns:
            Dictionary mapping feature names to values.
            Keys should be consistent across calls for the same detector.

        Example:
            {
                'total_packets': 1000,
                'unique_src_ips': 50,
                'average_packet_size': 100.5,
            }
        """
        pass

    def __call__(self, packets: List[Any]) -> Dict[str, Any]:
        """Allow feature extractor to be called as a function."""
        return self.extract(packets)
