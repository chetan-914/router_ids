# src/router_ids/models/ddos_model.py

import logging
from typing import Any, Dict

import numpy as np

from .ddos_detector import DDoSDetector

logger = logging.getLogger(__name__)


class DDoSModelRunner:
    """
    DDoS detection model runner that wraps the custom DDoSDetector class.
    """

    def __init__(self, model_path: str):
        """
        Initializes the runner by loading the model via DDoSDetector.

        Args:
            model_path: Path to the joblib file containing the model,
                        scaler, and label encoder.
        """
        self.detector = DDoSDetector()
        try:
            self.detector.load_model(model_path)
            logger.info(f"DDoSDetector model loaded successfully from {model_path}")
        except Exception as e:
            logger.error(f"Failed to load DDoSDetector model from {model_path}: {e}")
            raise

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs prediction using the loaded DDoSDetector model.

        Args:
            features: A dictionary of features extracted by DDoSFeatureExtractor.

        Returns:
            A dictionary with the detection results.
        """
        try:
            # Ensure the feature vector is in the correct order
            feature_vector = [
                features.get(name, 0.0) for name in self.detector.feature_names
            ]
            feature_array = np.array(feature_vector)

            # Get prediction from the custom detector
            prediction, probability = self.detector.predict(feature_array)

            is_attack = prediction[0] != 'BENIGN'
            confidence = max(probability[0])

            return {
                "detected": is_attack,
                "score": float(confidence),
                "label": prediction[0],
                "raw": features,
            }
        except Exception as e:
            logger.error(f"Error during DDoS prediction: {e}")
            return {
                "detected": False,
                "score": 0.0,
                "label": "error",
                "raw": features,
                "reason": str(e),
            }
        