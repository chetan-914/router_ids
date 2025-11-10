"""
Generate placeholder/dummy detection models.

Creates small scikit-learn models trained on synthetic data and saves them
with joblib for testing and deployment on Raspberry Pi.

These are intentionally simple and trained on synthetic data for demonstration.
In production, replace with real trained models.
"""

import os
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression


def generate_dummy_ddos_model(output_path: str) -> None:
    """Generate dummy DDoS detection model."""
    # Create synthetic training data
    np.random.seed(42)
    n_samples = 100
    
    # DDoS features: packet_rate, unique_src_ips, unique_dst_ips, 
    #                top_src_ratio, top_dst_ratio, udp_ratio, icmp_ratio,
    #                tcp_count, avg_packet_size, total_bytes
    X_benign = np.random.normal(
        loc=[100, 5, 5, 0.1, 0.05, 0.1, 0.05, 50, 100, 10000],
        scale=[50, 2, 2, 0.05, 0.02, 0.05, 0.02, 20, 30, 5000],
        size=(n_samples // 2, 10),
    )
    X_attack = np.random.normal(
        loc=[5000, 50, 5, 0.8, 0.3, 0.7, 0.2, 100, 50, 200000],
        scale=[1000, 10, 2, 0.1, 0.1, 0.1, 0.1, 30, 20, 50000],
        size=(n_samples // 2, 10),
    )
    
    X = np.vstack([X_benign, X_attack])
    y = np.hstack([np.zeros(n_samples // 2), np.ones(n_samples // 2)])
    
    # Train model
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X, y)
    
    # Save model
    joblib.dump(model, output_path)
    print(f"Generated DDoS model: {output_path}")


def generate_dummy_mitm_model(output_path: str) -> None:
    """Generate dummy MITM detection model."""
    np.random.seed(42)
    n_samples = 100
    
    # MITM features: arp_requests, arp_replies, arp_gratuitous,
    #                arp_request_ratio, arp_total, mac_ip_mismatch_count,
    #                ip_mac_mismatch_count, gratuitous_ratio, unique_arp_sources
    X_benign = np.random.normal(
        loc=[10, 10, 0, 0.5, 20, 0, 0, 0.0, 5],
        scale=[5, 5, 1, 0.1, 10, 1, 1, 0.05, 2],
        size=(n_samples // 2, 9),
    )
    X_attack = np.random.normal(
        loc=[100, 50, 20, 0.8, 150, 10, 8, 0.3, 30],
        scale=[30, 20, 10, 0.1, 50, 5, 3, 0.1, 10],
        size=(n_samples // 2, 9),
    )
    
    X = np.vstack([X_benign, X_attack])
    y = np.hstack([np.zeros(n_samples // 2), np.ones(n_samples // 2)])
    
    # Train model
    model = LogisticRegression(random_state=42)
    model.fit(X, y)
    
    # Save model
    joblib.dump(model, output_path)
    print(f"Generated MITM model: {output_path}")


def generate_dummy_c2c_model(output_path: str) -> None:
    """Generate dummy C2C detection model."""
    np.random.seed(42)
    n_samples = 100
    
    # C2C features: num_flows, average_flow_packets, max_flow_packets,
    #               unique_dst_ports, unique_src_ports, long_lived_flows,
    #               non_standard_dst_ports, flow_packet_variance
    X_benign = np.random.normal(
        loc=[50, 5, 20, 10, 30, 5, 8, 100],
        scale=[20, 2, 10, 5, 10, 2, 4, 50],
        size=(n_samples // 2, 8),
    )
    X_attack = np.random.normal(
        loc=[10, 50, 100, 5, 5, 8, 3, 20],
        scale=[5, 20, 30, 2, 2, 2, 2, 10],
        size=(n_samples // 2, 8),
    )
    
    X = np.vstack([X_benign, X_attack])
    y = np.hstack([np.zeros(n_samples // 2), np.ones(n_samples // 2)])
    
    # Train model
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X, y)
    
    # Save model
    joblib.dump(model, output_path)
    print(f"Generated C2C model: {output_path}")


def main() -> None:
    """Generate all dummy models."""
    # Determine output directory
    script_dir = Path(__file__).parent
    output_dir = script_dir
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate models
    generate_dummy_ddos_model(str(output_dir / "ddos_model.joblib"))
    generate_dummy_mitm_model(str(output_dir / "mitm_model.joblib"))
    generate_dummy_c2c_model(str(output_dir / "c2c_model.joblib"))
    
    print("All dummy models generated successfully!")


if __name__ == "__main__":
    main()
