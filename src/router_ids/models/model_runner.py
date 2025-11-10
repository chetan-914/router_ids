"""
Generic model runner for loading and running serialized models.

SECURITY NOTE:
Pickle files can execute arbitrary code. Only load pickles from trusted sources.
Production systems should use safer serialization formats (ONNX, protobuf, etc).
"""

import logging
from typing import Any, Dict

import joblib

logger = logging.getLogger(__name__)


class ModelRunner:
    """
    Load and run a serialized model on extracted features.

    Loads a joblib-serialized scikit-learn model and provides a consistent
    prediction interface.
    """

    def __init__(self, model_path: str):
        """
        Initialize ModelRunner with a model file.

        Args:
            model_path: Path to joblib-serialized model
        """
        self.model_path = model_path
        try:
            self.model = joblib.load(model_path)
            logger.info(f"Loaded model from {model_path}")
        except Exception as e:
            logger.error(f"Error loading model from {model_path}: {e}")
            raise

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run model prediction on features.

        Args:
            features: Dictionary of extracted features

        Returns:
            Prediction result with keys: label, score, raw
        """
        try:
            # Map features dict to feature vector
            # Subclasses should override this for detector-specific feature ordering
            feature_vector = self._features_to_vector(features)
            
            # Get prediction and probability
            prediction = self.model.predict([feature_vector])
            
            # Try to get probability scores
            if hasattr(self.model, "predict_proba"):
                probabilities = self.model.predict_proba([feature_vector])
                # Probability of positive class (attack)
                score = probabilities if len(probabilities) > 1 else probabilities
            else:
                score = float(prediction)

            return {
                "label": "attack" if prediction == 1 else "benign",
                "score": float(score),
                "raw": features,
            }

        except Exception as e:
            logger.error(f"Error running prediction: {e}")
            return {
                "label": "error",
                "score": 0.0,
                "raw": features,
                "error": str(e),
            }

    def _features_to_vector(self, features: Dict[str, Any]) -> list:
        """
        Convert feature dictionary to feature vector.

        Subclasses should override this to ensure correct feature ordering
        and handling.

        Args:
            features: Dictionary of features

        Returns:
            List of feature values
        """
        # Default: convert dict values to list in sorted key order
        return [features.get(key, 0.0) for key in sorted(features.keys())]
