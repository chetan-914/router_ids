"""C2C model runner wrapper."""

import logging
from typing import Any, Dict

from .model_runner import ModelRunner

logger = logging.getLogger(__name__)


class C2CModelRunner(ModelRunner):
    """C2C detection model runner."""

    FEATURE_KEYS = [
        "num_flows",
        "average_flow_packets",
        "max_flow_packets",
        "unique_dst_ports",
        "unique_src_ports",
        "long_lived_flows",
        "non_standard_dst_ports",
        "flow_packet_variance",
    ]

    def _features_to_vector(self, features: Dict[str, Any]) -> list:
        """
        Convert C2C features to feature vector.

        Ensures consistent ordering for model input.
        """
        return [features.get(key, 0.0) for key in self.FEATURE_KEYS]
