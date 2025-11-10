"""DDoS model runner wrapper."""

import logging
from typing import Any, Dict

from .model_runner import ModelRunner

logger = logging.getLogger(__name__)


class DDoSModelRunner(ModelRunner):
    """DDoS detection model runner."""

    FEATURE_KEYS = [
        "packet_rate",
        "unique_src_ips",
        "unique_dst_ips",
        "top_src_ratio",
        "top_dst_ratio",
        "udp_ratio",
        "icmp_ratio",
        "tcp_count",
        "avg_packet_size",
        "total_bytes",
    ]

    def _features_to_vector(self, features: Dict[str, Any]) -> list:
        """
        Convert DDoS features to feature vector.

        Ensures consistent ordering for model input.
        """
        return [features.get(key, 0.0) for key in self.FEATURE_KEYS]
