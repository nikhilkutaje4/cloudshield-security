import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (accuracy_score, classification_report, 
                              confusion_matrix)
import joblib
import os
import warnings
warnings.filterwarnings('ignore')

# ── NSL-KDD Column Names (41 features + label + difficulty) ─
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

# ── Map specific attacks into 5 categories ─────────────────
ATTACK_MAP = {
    # Normal
    'normal': 'Normal',
    
    # DoS attacks
    'neptune': 'DoS', 'back': 'DoS', 'land': 'DoS', 'pod': 'DoS',
    'smurf': 'DoS', 'teardrop': 'DoS', 'apache2': 'DoS',
    'udpstorm': 'DoS', 'processtable': 'DoS', 'worm': 'DoS',
    'mailbomb': 'DoS',
    
    # Probe attacks
    'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe',
    'satan': 'Probe', 'mscan': 'Probe', 'saint': 'Probe',
    
    # R2L attacks
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L',
    'multihop': 'R2L', 'phf': 'R2L', 'spy': 'R2L',
    'warezclient': 'R2L', 'warezmaster': 'R2L', 'sendmail': 'R2L',
    'named': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L',
    'xlock': 'R2L', 'xsnoop': 'R2L', 'httptunnel': 'R2L',
    
    # U2R attacks
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R',
    'rootkit': 'U2R', 'ps': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R'
}

def load_dataset(filepath):
    """Load NSL-KDD dataset"""
    print(f"[↓] Loading {filepath}...")
    df = pd.read_csv(filepath, header=None, names=COLUMNS)
    print(f"[✓] Loaded {len(df):,} records")
    return df

def preprocess(df, encoders=None, is_training=True):
    """Preprocess the dataset"""
    print("[⚙] Preprocessing...")
    
    # Drop difficulty column (not useful for prediction)
    df = df.drop(['difficulty'], axis=1)
    
    # Map attack labels into 5 broad categories
    df['label'] = df['label'].map(
        lambda x: ATTACK_MAP.get(x, 'Normal')
    )
    
    # Categorical columns to encode
    categorical_cols = ['protocol_type', 'service', 'flag']
    
    if is_training:
        encoders = {}
        for col in categorical_cols:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col])
            encoders[col] = le
    else:
        # Use existing encoders for test data
        for col in categorical_cols:
            le = encoders[col]
            # Handle unseen labels
            df[col] = df[col].map(
                lambda x: x if x in le.classes_ else le.classes_[0]
            )
            df[col] = le.transform(df[col])
    
    return df, encoders

def train_model():
    print("=" * 60)
    print("  CloudShield IDS - Random Forest Training")
    print("=" * 60)
    
    # ── Load data ──────────────────────────────────────────
    train_df = load_dataset('ids/data/KDDTrain+.txt')
    test_df = load_dataset('ids/data/KDDTest+.txt')
    
    # ── Preprocess ─────────────────────────────────────────
    train_df, encoders = preprocess(train_df, is_training=True)
    test_df, _ = preprocess(test_df, encoders=encoders, is_training=False)
    
    # ── Split features and labels ──────────────────────────
    X_train = train_df.drop('label', axis=1)
    y_train = train_df['label']
    X_test = test_df.drop('label', axis=1)
    y_test = test_df['label']
    
    print(f"\n[i] Training samples: {len(X_train):,}")
    print(f"[i] Testing samples:  {len(X_test):,}")
    print(f"[i] Features:         {X_train.shape[1]}")
    print(f"[i] Attack classes:   {sorted(y_train.unique())}")
    
    print("\n[i] Class distribution in training data:")
    print(y_train.value_counts().to_string())
    
    # ── Train Random Forest ────────────────────────────────
    print("\n[⚙] Training Random Forest (this takes 1-2 minutes)...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=25,
        min_samples_split=5,
        n_jobs=-1,
        random_state=42,
        verbose=0
    )
    model.fit(X_train, y_train)
    print("[✓] Model trained!")
    
    # ── Evaluate ───────────────────────────────────────────
    print("\n[⚙] Evaluating on test set...")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n{'=' * 60}")
    print(f"  ACCURACY: {accuracy * 100:.2f}%")
    print(f"{'=' * 60}\n")
    
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # ── Feature importance ─────────────────────────────────
    print("\n[i] Top 10 Most Important Features:")
    feature_imp = pd.DataFrame({
        'feature': X_train.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False).head(10)
    print(feature_imp.to_string(index=False))
    
    # ── Save model and encoders ────────────────────────────
    os.makedirs('models', exist_ok=True)
    joblib.dump(model, 'models/ids_model.pkl')
    joblib.dump(encoders, 'models/encoders.pkl')
    joblib.dump(list(X_train.columns), 'models/feature_names.pkl')
    
    # Save metadata for later use in Flask
    metadata = {
        'accuracy': float(accuracy),
        'classes': sorted(y_train.unique().tolist()),
        'n_features': int(X_train.shape[1]),
        'n_training_samples': int(len(X_train)),
        'top_features': feature_imp['feature'].tolist()
    }
    joblib.dump(metadata, 'models/metadata.pkl')
    
    print(f"\n[✓] Model saved to models/ids_model.pkl")
    print(f"[✓] Encoders saved to models/encoders.pkl")
    print(f"[✓] Metadata saved to models/metadata.pkl")
    print(f"\n[🎉] Training complete!\n")

if __name__ == '__main__':
    train_model()