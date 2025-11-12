"""
Generate placeholder/dummy detection models.

Creates small scikit-learn models trained on synthetic data and saves them
with joblib for testing and deployment.

These are intentionally simple and trained on synthetic data for demonstration.
In production, replace with real trained models.
"""

import os
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from .ddos_detector import DDoSDetector


def generate_dummy_ddos_model(output_path: str) -> None:
    """
    Generate dummy DDoS detection model using the custom DDoSDetector class.
    This will create a synthetic dataset, train a model, and save it
    along with its scaler and encoders.
    """
    print("--- Generating DDoS model with DDoSDetector ---")
    detector = DDoSDetector(model_type='random_forest')
    detector.train()
    detector.save_model(output_path)
    print(f"Generated DDoS model bundle: {output_path}")


def generate_dummy_mitm_model(output_dir: str) -> None:
    """
    Generate a dummy multi-class MITM model and its scaler.
    Saves two files: mitm_model.joblib and mitm_scaler.joblib.
    """
    print("--- Generating dummy MITM model and scaler ---")
    np.random.seed(42)
    n_samples = 300
    
    # Features: 'mac_ip_inconsistency', 'packet_in_count', 'packet_rate', 'rtt (avg)',
    #           'is_broadcast', 'arp_request', 'arp_reply', 'op_code(arp)'
    # Classes: 0=Normal, 1=Suspicious, 2=Attack
    
    # Generate synthetic data for each class
    X_normal = np.random.normal(loc=[0, 5000, 0.01, 0.1, 0, 1, 1, 1], scale=[0, 1000, 0.005, 0.05, 0, 0, 0, 0], size=(n_samples // 2, 8))
    X_suspicious = np.random.normal(loc=[1, 10000, 0.03, 0.2, 1, 1, 0, 2], scale=[0, 2000, 0.01, 0.1, 0, 0, 0, 0], size=(n_samples // 3, 8))
    X_attack = np.random.normal(loc=[5, 25000, 0.08, 0.5, 1, 0, 1, 2], scale=[2, 5000, 0.02, 0.2, 0, 0, 0, 0], size=(n_samples - len(X_normal) - len(X_suspicious), 8))

    X = np.vstack([X_normal, X_suspicious, X_attack])
    y = np.concatenate([
        np.zeros(len(X_normal)), 
        np.ones(len(X_suspicious)), 
        np.full(len(X_attack), 2)
    ])
    
    # Train a scaler on the data
    scaler = StandardScaler()
    scaler.fit(X)
    
    # Train a multi-class classification model
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X, y)
    
    # Save both the model and the scaler as separate files
    joblib.dump(model, os.path.join(output_dir, "mitm_model.joblib"))
    joblib.dump(scaler, os.path.join(output_dir, "mitm_scaler.joblib"))
    print(f"Generated MITM model and scaler in: {output_dir}")


def generate_dummy_c2c_model(output_dir: str) -> None:
    """
    Generate a dummy C2C model, scaler, and encoder.
    Saves three files.
    """
    print("--- Generating dummy C2C model, scaler, and encoder ---")
    np.random.seed(42)
    n_samples = 200

    # --- Generate dummy raw categorical data ---
    protos = np.random.choice(['tcp', 'udp', 'icmp'], n_samples)
    services = np.random.choice(['http', 'dns', 'unknown', 'ssl'], n_samples)
    conn_states = np.random.choice(['SF', 'S0', 'REJ', 'OTH'], n_samples)
    histories = np.random.choice(['S', 'SA', 'D', 'DF'], n_samples)
    categorical_data = np.vstack([protos, services, conn_states, histories]).T

    # --- Train Encoder ---
    encoder = OneHotEncoder(handle_unknown='ignore')
    encoder.fit(categorical_data)
    encoded_categorical = encoder.transform(categorical_data).toarray()
    
    # --- Generate dummy raw numeric data ---
    # Based on the 14 numeric features in the pipeline
    numeric_data = np.random.rand(n_samples, 14)
    y = np.random.randint(0, 2, n_samples) # Random labels (0 or 1)
    
    # --- Train Scaler ---
    scaler = StandardScaler()
    scaler.fit(numeric_data)

    # --- Train Model ---
    # Combine processed features to create training data for the model
    X = np.hstack([numeric_data, encoded_categorical])
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X, y)
    
    # --- Save Artifacts ---
    joblib.dump(model, os.path.join(output_dir, "c2c_detection_model.joblib"))
    joblib.dump(scaler, os.path.join(output_dir, "c2_scaler.joblib"))
    joblib.dump(encoder, os.path.join(output_dir, "c2_encoder.joblib"))
    print(f"Generated C2C artifacts in: {output_dir}")


def main() -> None:
    """Generate all dummy models."""
    # Determine the correct output directory
    script_dir = Path(__file__).parent
    output_dir = script_dir / "model_joblib"
    
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate all models, passing the correct paths
    generate_dummy_ddos_model(str(output_dir / "ddos_model.joblib"))
    generate_dummy_mitm_model(str(output_dir))
    generate_dummy_c2c_model(str(output_dir))
    
    print("\nAll dummy models generated successfully!")


if __name__ == "__main__":
    main()