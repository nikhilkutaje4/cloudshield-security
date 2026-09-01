import joblib
import numpy as np
import pandas as pd
import os

# ── Global model cache (load once) ─────────────────────────
_model = None
_encoders = None
_feature_names = None
_metadata = None

def load_model():
    """Load model into memory (only once)"""
    global _model, _encoders, _feature_names, _metadata
    
    if _model is None:
        print("[i] Loading IDS model into memory...")
        _model = joblib.load('models/ids_model.pkl')
        _encoders = joblib.load('models/encoders.pkl')
        _feature_names = joblib.load('models/feature_names.pkl')
        _metadata = joblib.load('models/metadata.pkl')
        print(f"[✓] Model loaded. Accuracy: {_metadata['accuracy']*100:.2f}%")
    
    return _model, _encoders, _feature_names, _metadata

def get_metadata():
    """Return model metadata"""
    load_model()
    return _metadata

# ── Threat level mapping ───────────────────────────────────
THREAT_LEVELS = {
    'Normal': 'Normal',
    'Probe': 'Low',
    'DoS': 'High',
    'R2L': 'High',
    'U2R': 'High'
}

ATTACK_DESCRIPTIONS = {
    'Normal': 'Legitimate traffic',
    'Probe': 'Reconnaissance / port scanning',
    'DoS': 'Denial of Service attack',
    'R2L': 'Remote to Local attack (brute force / unauthorized access)',
    'U2R': 'User to Root privilege escalation'
}

def predict_traffic(features_dict):
    """
    Predict if network traffic is normal or an attack.
    features_dict: dict of 41 network features
    Returns: dict with prediction details
    """
    model, encoders, feature_names, metadata = load_model()
    
    # Convert to DataFrame
    df = pd.DataFrame([features_dict])
    
    # Encode categorical features
    for col in ['protocol_type', 'service', 'flag']:
        if col in df.columns:
            le = encoders[col]
            df[col] = df[col].apply(
                lambda x: x if x in le.classes_ else le.classes_[0]
            )
            df[col] = le.transform(df[col])
    
    # Ensure column order matches training
    df = df[feature_names]
    
    # Predict
    prediction = model.predict(df)[0]
    probabilities = model.predict_proba(df)[0]
    confidence = float(max(probabilities) * 100)
    
    return {
        'prediction': prediction,
        'threat_level': THREAT_LEVELS.get(prediction, 'Unknown'),
        'confidence': round(confidence, 2),
        'description': ATTACK_DESCRIPTIONS.get(prediction, ''),
        'is_attack': prediction != 'Normal'
    }

# ── Predefined sample traffic patterns ─────────────────────
SAMPLE_TRAFFIC = {
    'normal_http': {
        'duration': 0, 'protocol_type': 'tcp', 'service': 'http',
        'flag': 'SF', 'src_bytes': 232, 'dst_bytes': 8153,
        'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0,
        'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 0,
        'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
        'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
        'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
        'count': 5, 'srv_count': 5, 'serror_rate': 0.0,
        'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
        'same_srv_rate': 1.0, 'diff_srv_rate': 0.0,
        'srv_diff_host_rate': 0.0, 'dst_host_count': 30,
        'dst_host_srv_count': 255, 'dst_host_same_srv_rate': 1.0,
        'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.03,
        'dst_host_srv_diff_host_rate': 0.04, 'dst_host_serror_rate': 0.0,
        'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
        'dst_host_srv_rerror_rate': 0.0
    },
    'dos_neptune': {
        'duration': 0, 'protocol_type': 'tcp', 'service': 'private',
        'flag': 'S0', 'src_bytes': 0, 'dst_bytes': 0,
        'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0,
        'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0,
        'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
        'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
        'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
        'count': 123, 'srv_count': 6, 'serror_rate': 1.0,
        'srv_serror_rate': 1.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
        'same_srv_rate': 0.05, 'diff_srv_rate': 0.07,
        'srv_diff_host_rate': 0.0, 'dst_host_count': 255,
        'dst_host_srv_count': 26, 'dst_host_same_srv_rate': 0.10,
        'dst_host_diff_srv_rate': 0.05, 'dst_host_same_src_port_rate': 0.0,
        'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 1.0,
        'dst_host_srv_serror_rate': 1.0, 'dst_host_rerror_rate': 0.0,
        'dst_host_srv_rerror_rate': 0.0
    },
    'probe_portscan': {
        'duration': 0, 'protocol_type': 'tcp', 'service': 'private',
        'flag': 'REJ', 'src_bytes': 0, 'dst_bytes': 0,
        'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0,
        'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0,
        'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
        'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
        'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
        'count': 229, 'srv_count': 10, 'serror_rate': 0.0,
        'srv_serror_rate': 0.0, 'rerror_rate': 1.0, 'srv_rerror_rate': 1.0,
        'same_srv_rate': 0.04, 'diff_srv_rate': 0.06,
        'srv_diff_host_rate': 0.0, 'dst_host_count': 255,
        'dst_host_srv_count': 10, 'dst_host_same_srv_rate': 0.04,
        'dst_host_diff_srv_rate': 0.06, 'dst_host_same_src_port_rate': 0.0,
        'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
        'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 1.0,
        'dst_host_srv_rerror_rate': 1.0
    },
    'r2l_bruteforce': {
        'duration': 30, 'protocol_type': 'tcp', 'service': 'ftp',
        'flag': 'SF', 'src_bytes': 200, 'dst_bytes': 300,
        'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 5,
        'num_failed_logins': 5, 'logged_in': 0, 'num_compromised': 0,
        'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
        'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
        'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 1,
        'count': 1, 'srv_count': 1, 'serror_rate': 0.0,
        'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
        'same_srv_rate': 1.0, 'diff_srv_rate': 0.0,
        'srv_diff_host_rate': 0.0, 'dst_host_count': 10,
        'dst_host_srv_count': 10, 'dst_host_same_srv_rate': 1.0,
        'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.10,
        'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
        'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
        'dst_host_srv_rerror_rate': 0.0
    },
    'u2r_rootkit': {
        'duration': 200, 'protocol_type': 'tcp', 'service': 'telnet',
        'flag': 'SF', 'src_bytes': 500, 'dst_bytes': 3000,
        'land': 0, 'wrong_fragment': 0, 'urgent': 3, 'hot': 15,
        'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 5,
        'root_shell': 1, 'su_attempted': 2, 'num_root': 10,
        'num_file_creations': 5, 'num_shells': 2, 'num_access_files': 3,
        'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
        'count': 1, 'srv_count': 1, 'serror_rate': 0.0,
        'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
        'same_srv_rate': 1.0, 'diff_srv_rate': 0.0,
        'srv_diff_host_rate': 0.0, 'dst_host_count': 1,
        'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 1.0,
        'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 1.0,
        'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
        'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
        'dst_host_srv_rerror_rate': 0.0
    }
}

# ── Quick test ─────────────────────────────────────────────
if __name__ == '__main__':
    print("Testing IDS predictions on sample traffic...\n")
    for name, features in SAMPLE_TRAFFIC.items():
        result = predict_traffic(features)
        icon = "✅" if not result['is_attack'] else "🚨"
        print(f"{icon} {name}")
        print(f"   Predicted: {result['prediction']}")
        print(f"   Threat:    {result['threat_level']}")
        print(f"   Confidence: {result['confidence']}%")
        print(f"   Info: {result['description']}\n")