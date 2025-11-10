# src/router_ids/models/ddos_detector.py

import os
import warnings
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.svm import SVC

warnings.filterwarnings('ignore')


class DDoSDetector:
    def __init__(self, model_type='random_forest'):
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_names = None
        self.is_trained = False

    def _get_model(self):
        """Get the appropriate model based on model_type"""
        models = {
            'random_forest': RandomForestClassifier(
                n_estimators=50,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            ),
            'logistic_regression': LogisticRegression(
                random_state=42,
                max_iter=1000
            ),
            'svm': SVC(
                kernel='rbf',
                random_state=42,
                probability=True
            )
        }
        return models.get(self.model_type, models['random_forest'])

    def create_synthetic_dataset(self, n_samples=10000):
        """Create a synthetic dataset for training."""
        print("Creating synthetic network traffic dataset...")
        np.random.seed(42)
        features = []
        labels = []

        for i in range(n_samples):
            if i < n_samples * 0.8:  # 80% normal traffic
                packet_size = np.random.normal(500, 200)
                packets_per_sec = np.random.normal(10, 5)
                flow_duration = np.random.exponential(30)
                bytes_per_sec = packet_size * packets_per_sec
                unique_ips = np.random.poisson(3)
                port_diversity = np.random.poisson(2)
                tcp_ratio = np.random.beta(7, 3)
                udp_ratio = 1 - tcp_ratio
                syn_flag_ratio = np.random.beta(2, 8)
                ack_flag_ratio = np.random.beta(8, 2)
                label = 'BENIGN'
            else:  # 20% attack traffic
                packet_size = np.random.normal(64, 20)
                packets_per_sec = np.random.normal(100, 30)
                flow_duration = np.random.exponential(5)
                bytes_per_sec = packet_size * packets_per_sec
                unique_ips = np.random.poisson(50)
                port_diversity = np.random.poisson(1)
                tcp_ratio = np.random.beta(3, 7)
                udp_ratio = 1 - tcp_ratio
                syn_flag_ratio = np.random.beta(8, 2)
                ack_flag_ratio = np.random.beta(2, 8)
                label = np.random.choice(['DDoS-TCP', 'DDoS-UDP', 'DDoS-ICMP'])

            features.append([
                max(packet_size, 1), max(packets_per_sec, 0.1),
                max(flow_duration, 0.1), max(bytes_per_sec, 1),
                max(unique_ips, 1), max(port_diversity, 1),
                max(min(tcp_ratio, 1), 0), max(min(udp_ratio, 1), 0),
                max(min(syn_flag_ratio, 1), 0), max(min(ack_flag_ratio, 1), 0)
            ])
            labels.append(label)

        feature_names = [
            'Packet_Size', 'Packets_Per_Sec', 'Flow_Duration', 'Bytes_Per_Sec',
            'Unique_IPs', 'Port_Diversity', 'TCP_Ratio', 'UDP_Ratio',
            'SYN_Flag_Ratio', 'ACK_Flag_Ratio'
        ]
        df = pd.DataFrame(features, columns=feature_names)
        df['Label'] = labels
        return df

    def preprocess_data(self, df):
        """Preprocess the dataset."""
        df = df.fillna(df.mean(numeric_only=True))
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.fillna(df.mean(numeric_only=True))

        X = df.drop(['Label'], axis=1)
        y = df['Label']
        self.feature_names = X.columns.tolist()
        y_encoded = self.label_encoder.fit_transform(y)
        X_scaled = self.scaler.fit_transform(X)
        return X_scaled, y_encoded

    def train(self, dataset_path=None):
        """Train the DDoS detection model."""
        df = self.create_synthetic_dataset()
        X, y = self.preprocess_data(df)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        self.model = self._get_model()
        self.model.fit(X_train, y_train)
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"\nModel Accuracy: {accuracy:.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=self.label_encoder.classes_))
        self.is_trained = True

    def predict(self, features):
        """Predict whether traffic is malicious or benign."""
        if not self.is_trained:
            raise ValueError("Model not trained.")
        if len(features.shape) == 1:
            features = features.reshape(1, -1)
        features_scaled = self.scaler.transform(features)
        prediction = self.model.predict(features_scaled)
        probability = self.model.predict_proba(features_scaled)
        predicted_labels = self.label_encoder.inverse_transform(prediction)
        return predicted_labels, probability

    def save_model(self, model_path):
        """Save the trained model."""
        if not self.is_trained:
            raise ValueError("Model must be trained before saving.")
        model_data = {
            'model': self.model, 'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'feature_names': self.feature_names,
            'model_type': self.model_type
        }
        joblib.dump(model_data, model_path)
        print(f"Model saved to {model_path}")

    def load_model(self, model_path):
        """Load a pre-trained model."""
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")
        model_data = joblib.load(model_path)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.label_encoder = model_data['label_encoder']
        self.feature_names = model_data['feature_names']
        self.model_type = model_data['model_type']
        self.is_trained = True
        print(f"Model loaded from {model_path}")