"""MITM model runner wrapper."""

import logging
from typing import Any, Dict

from .model_runner import ModelRunner

logger = logging.getLogger(__name__)


class MITMModelRunner(ModelRunner):
    """MITM detection model runner."""

    FEATURE_KEYS = [
        "arp_requests",
        "arp_replies",
        "arp_gratuitous",
        "arp_request_ratio",
        "arp_total",
        "mac_ip_mismatch_count",
        "ip_mac_mismatch_count",
        "gratuitous_ratio",
        "unique_arp_sources",
    ]

    def _features_to_vector(self, features: Dict[str, Any]) -> list:
        """
        Convert MITM features to feature vector.

        Ensures consistent ordering for model input.
        """
        return [features.get(key, 0.0) for key in self.FEATURE_KEYS]
