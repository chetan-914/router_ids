"""
C2C model runner for the custom RandomForest model.
"""

import logging
from typing import Any, Dict

import joblib
import numpy as np

logger = logging.getLogger(__name__)


class C2CModelRunner:
    """
    Wraps the custom C2C model that uses separate scaler and encoder artifacts
    and a complex feature engineering pipeline.
    """

    def __init__(self, model_path: str, scaler_path: str, encoder_path: str, threshold: float):
        """
        Initializes by loading model, scaler, encoder, and prediction threshold.
        """
        self.prediction_threshold = threshold
        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.encoder = joblib.load(encoder_path)
            logger.info(f"Custom C2C model loaded from {model_path}")
            logger.info(f"Custom C2C scaler loaded from {scaler_path}")
            logger.info(f"Custom C2C encoder loaded from {encoder_path}")
        except Exception as e:
            logger.error(f"Failed to load C2C model artifacts: {e}")
            raise

    def predict(self, raw_features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs the full preprocessing pipeline and prediction.
        """
        try:
            final_features = self._preprocess(raw_features)
            
            # Predict probability of being malicious (class 1)
            probability = self.model.predict_proba(final_features)[0, 1]
            detected = probability >= self.prediction_threshold
            label = "malicious" if detected else "benign"

            return {
                "detected": detected,
                "score": float(probability),
                "label": label,
                "raw": raw_features,
            }
        except Exception as e:
            logger.error(f"Error during C2C prediction: {e}", exc_info=True)
            return {
                "detected": False, "score": 0.0, "label": "error",
                "raw": raw_features, "reason": str(e),
            }

    def _preprocess(self, features: Dict[str, Any]) -> np.ndarray:
        """Replicates the feature engineering and preprocessing pipeline."""
        # --- Feature Engineering ---
        duration = float(features.get("duration", 0.0))
        orig_bytes = float(features.get("orig_bytes", 0.0))
        resp_bytes = float(features.get("resp_bytes", 0.0))
        orig_pkts = float(features.get("orig_pkts", 0.0))
        resp_pkts = float(features.get("resp_pkts", 0.0))

        packet_rate = orig_pkts / (duration + 1e-6)
        orig_bytes_per_pkt = orig_bytes / (orig_pkts + 1)
        resp_bytes_per_pkt = resp_bytes / (resp_pkts + 1)
        pkt_ratio = orig_pkts / (resp_pkts + 1)
        byte_ratio = orig_bytes / (resp_bytes + 1)
        total_pkts = orig_pkts + resp_pkts
        total_bytes = orig_bytes + resp_bytes
        has_response = 1.0 if resp_pkts > 0 else 0.0
        bytes_per_sec = total_bytes / (duration + 1e-6)
        
        numeric_features = np.array([[
            duration, orig_bytes, resp_bytes, orig_pkts, resp_pkts,
            packet_rate, orig_bytes_per_pkt, resp_bytes_per_pkt,
            pkt_ratio, byte_ratio, total_pkts, total_bytes,
            has_response, bytes_per_sec
        ]])

        # --- Categorical Encoding ---
        proto = features.get("proto", "-")
        service = features.get("service", "-")
        conn_state = features.get("conn_state", "-")
        history = features.get("history", "-")

        # Handle unknown categories by mapping them to a known 'other' category if needed
        # This requires knowing how the encoder was trained. Assuming it can handle unknowns
        # or they should be mapped to a default like 'OTH' or 'unknown'.
        categorical_data = np.array([[proto, service, conn_state, history]])
        
        try:
            encoded_categorical = self.encoder.transform(categorical_data).toarray()
        except ValueError as e:
            # Fallback for categories not seen during training
            logger.warning(f"Categorical feature not seen during training: {e}. Using fallback.")
            # Create zero array with correct shape
            num_categories = self.encoder.categories_[0].size + self.encoder.categories_[1].size + self.encoder.categories_[2].size + self.encoder.categories_[3].size
            encoded_categorical = np.zeros((1, num_categories))


        # --- Scaling and Combining ---
        numeric_features_scaled = self.scaler.transform(numeric_features)
        final_features = np.hstack([numeric_features_scaled, encoded_categorical])
        
        return final_features