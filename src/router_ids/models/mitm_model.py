"""
MITM model runner for the custom Random Forest multi-class model.
"""

import logging
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


class MITMModelRunner:
    """
    Wraps the custom MITM model that uses a separate scaler and produces
    multi-class predictions (Normal, Suspicious, Attack).
    """
    FEATURE_KEYS = [
        'mac_ip_inconsistency', 'packet_in_count', 'packet_rate', 'rtt (avg)',
        'is_broadcast', 'arp_request', 'arp_reply', 'op_code(arp)'
    ]
    LABEL_MAP = {0: "Normal", 1: "Suspicious", 2: "Attack"}

    def __init__(self, model_path: str, scaler_path: str):
        """
        Initializes the runner by loading both the model and the scaler.
        """
        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            logger.info(f"Custom MITM model loaded from {model_path}")
            logger.info(f"Custom MITM scaler loaded from {scaler_path}")
        except Exception as e:
            logger.error(f"Failed to load MITM model/scaler: {e}")
            raise

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs prediction using the loaded model and scaler.
        """
        try:
            # Create a DataFrame to ensure correct feature order and naming
            df = pd.DataFrame([features], columns=self.FEATURE_KEYS)

            # Scale features and make prediction
            X_scaled = self.scaler.transform(df)
            probabilities = self.model.predict_proba(X_scaled)[0]
            prediction_idx = np.argmax(probabilities)
            
            label = self.LABEL_MAP.get(prediction_idx, "Unknown")
            score = float(probabilities[prediction_idx])
            
            # An attack is detected if the label is "Suspicious" or "Attack"
            detected = label in ["Suspicious", "Attack"]

            return {
                "detected": detected,
                "score": score,  # Confidence of the predicted class
                "label": label,
                "raw": features,
                "all_probabilities": {self.LABEL_MAP.get(i): prob for i, prob in enumerate(probabilities)}
            }
        except Exception as e:
            logger.error(f"Error during MITM prediction: {e}")
            return {
                "detected": False, "score": 0.0, "label": "error",
                "raw": features, "reason": str(e),
            }