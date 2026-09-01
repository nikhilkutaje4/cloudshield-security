"""
Autoencoder Anomaly Detector
────────────────────────────
Trains a neural network autoencoder ONLY on normal traffic.
When shown attack traffic, reconstruction error spikes → ANOMALY DETECTED

Architecture:
  Input(41) → Encoder(32→16→8) → Decoder(16→32→41)

This is a genuine deep learning autoencoder using
scikit-learn's MLPRegressor (multi-layer perceptron).
"""

import pandas as pd
import numpy as np
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
import os
import warnings
warnings.filterwarnings('ignore')

# ── Column names (same as train.py) ────────────────────────
COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

def train_autoencoder():
    print("=" * 65)
    print("  CloudShield IDS — Autoencoder Training")
    print("=" * 65)
    
    # ── Load dataset ───────────────────────────────────────
    print("\n[↓] Loading NSL-KDD training data...")
    df = pd.read_csv('ids/data/KDDTrain+.txt', header=None, names=COLUMNS)
    print(f"[✓] Loaded {len(df):,} records")
    
    # Drop difficulty
    df = df.drop(['difficulty'], axis=1)
    
    # ── Keep ONLY normal traffic for training ──────────────
    normal_df = df[df['label'] == 'normal'].copy()
    attack_df = df[df['label'] != 'normal'].copy()
    print(f"[i] Normal samples: {len(normal_df):,}")
    print(f"[i] Attack samples: {len(attack_df):,} (used for validation)")
    
    # ── Encode categorical features ────────────────────────
    encoders = {}
    for col in ['protocol_type', 'service', 'flag']:
        le = LabelEncoder()
        # Fit on ALL data so we handle test-time unseen labels
        le.fit(df[col])
        normal_df[col] = le.transform(normal_df[col])
        attack_df[col] = le.transform(attack_df[col])
        encoders[col] = le
    
    # Drop label column
    X_normal = normal_df.drop('label', axis=1)
    X_attack = attack_df.drop('label', axis=1)
    
    feature_names = list(X_normal.columns)
    
    # ── Scale features ─────────────────────────────────────
    print("\n[⚙] Scaling features...")
    scaler = StandardScaler()
    X_normal_scaled = scaler.fit_transform(X_normal)
    X_attack_scaled = scaler.transform(X_attack)
    
    # ── Build autoencoder ──────────────────────────────────
    print("\n[⚙] Training Autoencoder...")
    print("[i] Architecture: 41 → 32 → 16 → 8 → 16 → 32 → 41")
    print("[i] This takes 2-4 minutes...\n")
    
    autoencoder = MLPRegressor(
        hidden_layer_sizes=(32, 16, 8, 16, 32),
        activation='relu',
        solver='adam',
        learning_rate_init=0.001,
        max_iter=50,
        batch_size=256,
        early_stopping=True,
        validation_fraction=0.1,
        random_state=42,
        verbose=True
    )
    
    # Train: input == output (that's how autoencoders work)
    autoencoder.fit(X_normal_scaled, X_normal_scaled)
    
    print("\n[✓] Autoencoder trained!")
    
    # ── Calculate reconstruction errors ────────────────────
    print("\n[⚙] Calculating reconstruction errors...")
    
    normal_reconstructed = autoencoder.predict(X_normal_scaled)
    normal_errors = np.mean(
        np.square(X_normal_scaled - normal_reconstructed), axis=1
    )
    
    attack_reconstructed = autoencoder.predict(X_attack_scaled)
    attack_errors = np.mean(
        np.square(X_attack_scaled - attack_reconstructed), axis=1
    )
    
    # ── Determine threshold ────────────────────────────────
    # Use 95th percentile of normal errors as threshold
    threshold = float(np.percentile(normal_errors, 95))
    
    # ── Statistics ─────────────────────────────────────────
    print(f"\n{'─' * 65}")
    print("  RECONSTRUCTION ERROR STATISTICS")
    print(f"{'─' * 65}")
    print(f"\n  NORMAL traffic errors:")
    print(f"    Mean:   {normal_errors.mean():.4f}")
    print(f"    Median: {np.median(normal_errors):.4f}")
    print(f"    95th %: {threshold:.4f}  ← THRESHOLD")
    print(f"    Max:    {normal_errors.max():.4f}")
    
    print(f"\n  ATTACK traffic errors:")
    print(f"    Mean:   {attack_errors.mean():.4f}")
    print(f"    Median: {np.median(attack_errors):.4f}")
    print(f"    Max:    {attack_errors.max():.4f}")
    
    # ── Performance ────────────────────────────────────────
    normal_correct = np.sum(normal_errors <= threshold)
    attack_correct = np.sum(attack_errors > threshold)
    total_correct = normal_correct + attack_correct
    total_samples = len(normal_errors) + len(attack_errors)
    accuracy = total_correct / total_samples
    
    normal_accuracy = normal_correct / len(normal_errors)
    attack_detection_rate = attack_correct / len(attack_errors)
    
    print(f"\n{'─' * 65}")
    print("  ANOMALY DETECTION PERFORMANCE")
    print(f"{'─' * 65}")
    print(f"  Normal traffic accuracy:  {normal_accuracy * 100:.2f}%")
    print(f"  Attack detection rate:    {attack_detection_rate * 100:.2f}%")
    print(f"  Overall accuracy:         {accuracy * 100:.2f}%")
    print(f"{'─' * 65}")
    
    # ── Save everything ────────────────────────────────────
    os.makedirs('models', exist_ok=True)
    joblib.dump(autoencoder, 'models/autoencoder.pkl')
    joblib.dump(scaler, 'models/ae_scaler.pkl')
    joblib.dump(encoders, 'models/ae_encoders.pkl')
    joblib.dump(feature_names, 'models/ae_feature_names.pkl')
    
    metadata = {
        'threshold': threshold,
        'normal_mean_error': float(normal_errors.mean()),
        'attack_mean_error': float(attack_errors.mean()),
        'normal_accuracy': float(normal_accuracy),
        'attack_detection_rate': float(attack_detection_rate),
        'overall_accuracy': float(accuracy),
        'training_samples': int(len(X_normal)),
        'architecture': '41 → 32 → 16 → 8 → 16 → 32 → 41'
    }
    joblib.dump(metadata, 'models/ae_metadata.pkl')
    
    print(f"\n[✓] Autoencoder saved to models/autoencoder.pkl")
    print(f"[✓] Metadata saved to models/ae_metadata.pkl")
    print(f"[🎉] Training complete!\n")

if __name__ == '__main__':
    train_autoencoder()