"""
SHAP Explainability Module
──────────────────────────
Explains WHY the IDS model made each prediction.
Uses SHAP (SHapley Additive exPlanations) — 
the industry standard for ML explainability.
"""

import joblib
import numpy as np
import pandas as pd
import shap
import os
import warnings
warnings.filterwarnings('ignore')

# ── Global cache ───────────────────────────────────────────
_explainer = None
_model = None
_encoders = None
_feature_names = None

def load_explainer():
    """Load SHAP explainer (only once, cached in memory)"""
    global _explainer, _model, _encoders, _feature_names
    
    if _explainer is None:
        print("[i] Loading SHAP explainer...")
        _model = joblib.load('models/ids_model.pkl')
        _encoders = joblib.load('models/encoders.pkl')
        _feature_names = joblib.load('models/feature_names.pkl')
        
        # TreeExplainer is optimized for Random Forest
        _explainer = shap.TreeExplainer(_model)
        print("[✓] SHAP explainer ready")
    
    return _explainer, _model, _encoders, _feature_names

# ── Human-friendly feature descriptions ────────────────────
FEATURE_DESCRIPTIONS = {
    'duration': 'Connection duration',
    'protocol_type': 'Network protocol (TCP/UDP/ICMP)',
    'service': 'Target service (HTTP/FTP/etc)',
    'flag': 'Connection status flag',
    'src_bytes': 'Bytes sent from source',
    'dst_bytes': 'Bytes sent to destination',
    'land': 'Same source/dest IP (spoofing)',
    'wrong_fragment': 'Wrong fragment count',
    'urgent': 'Urgent packets',
    'hot': 'Sensitive access indicators',
    'num_failed_logins': 'Failed login attempts',
    'logged_in': 'Successfully logged in',
    'num_compromised': 'Compromised conditions',
    'root_shell': 'Root shell obtained',
    'su_attempted': 'SU command attempts',
    'num_root': 'Root accesses',
    'num_file_creations': 'File creations',
    'num_shells': 'Shell prompts opened',
    'num_access_files': 'Access control file ops',
    'num_outbound_cmds': 'Outbound commands',
    'is_host_login': 'Login as system host',
    'is_guest_login': 'Login as guest',
    'count': 'Connections to same host',
    'srv_count': 'Connections to same service',
    'serror_rate': 'SYN error rate',
    'srv_serror_rate': 'Service SYN error rate',
    'rerror_rate': 'REJ error rate',
    'srv_rerror_rate': 'Service REJ error rate',
    'same_srv_rate': 'Same service connection rate',
    'diff_srv_rate': 'Different service rate',
    'srv_diff_host_rate': 'Different host per service',
    'dst_host_count': 'Dest host connections',
    'dst_host_srv_count': 'Dest host service count',
    'dst_host_same_srv_rate': 'Dest host same-service rate',
    'dst_host_diff_srv_rate': 'Dest host diff-service rate',
    'dst_host_same_src_port_rate': 'Same source port rate',
    'dst_host_srv_diff_host_rate': 'Service diff host rate',
    'dst_host_serror_rate': 'Dest host SYN error rate',
    'dst_host_srv_serror_rate': 'Dest host service SYN error',
    'dst_host_rerror_rate': 'Dest host REJ error rate',
    'dst_host_srv_rerror_rate': 'Dest host service REJ error'
}

def explain_prediction(features_dict, prediction, top_n=5):
    """
    Explain why the model made a specific prediction.
    Returns top N features that contributed most.
    """
    explainer, model, encoders, feature_names = load_explainer()
    
    # Convert to DataFrame
    df = pd.DataFrame([features_dict])
    
    # Encode categorical features (same as predict.py)
    for col in ['protocol_type', 'service', 'flag']:
        if col in df.columns:
            le = encoders[col]
            df[col] = df[col].apply(
                lambda x: x if x in le.classes_ else le.classes_[0]
            )
            df[col] = le.transform(df[col])
    
    df = df[feature_names]
    
    # Get SHAP values
    shap_values = explainer.shap_values(df)
    
    # Get the class index for our prediction
    classes = list(model.classes_)
    if prediction not in classes:
        return []
    class_idx = classes.index(prediction)
    
    # Extract SHAP values for this prediction
    # New SHAP: shape is (samples, features, classes)
    # Old SHAP: list of arrays, one per class
    if isinstance(shap_values, list):
        # Old API - list of arrays
        values = shap_values[class_idx][0]
    else:
        # New API - 3D array
        if len(shap_values.shape) == 3:
            values = shap_values[0, :, class_idx]
        else:
            values = shap_values[0]
    
    # Build feature contribution list
    contributions = []
    for i, feat in enumerate(feature_names):
        contributions.append({
            'feature': feat,
            'description': FEATURE_DESCRIPTIONS.get(feat, feat),
            'value': float(df[feat].iloc[0]),
            'shap_value': float(values[i]),
            'abs_impact': abs(float(values[i]))
        })
    
    # Sort by absolute impact (most influential first)
    contributions.sort(key=lambda x: x['abs_impact'], reverse=True)
    top_features = contributions[:top_n]
    
    # Calculate percentage contribution
    total_impact = sum(f['abs_impact'] for f in top_features)
    if total_impact > 0:
        for f in top_features:
            f['percentage'] = round((f['abs_impact'] / total_impact) * 100, 1)
            f['direction'] = 'increase' if f['shap_value'] > 0 else 'decrease'
    else:
        for f in top_features:
            f['percentage'] = 0
            f['direction'] = 'neutral'
    
    return top_features

# ── Self test ──────────────────────────────────────────────
if __name__ == '__main__':
    from ids.predict import SAMPLE_TRAFFIC, predict_traffic
    
    print(f"\n{'═'*70}")
    print(f"  SHAP Explainability Test")
    print(f"{'═'*70}\n")
    
    # Test on DoS attack
    features = SAMPLE_TRAFFIC['dos_neptune']
    result = predict_traffic(features)
    
    print(f"Prediction: {result['prediction']} ({result['confidence']}%)\n")
    print(f"Top 5 features driving this decision:\n")
    
    explanation = explain_prediction(features, result['prediction'])
    
    for i, feat in enumerate(explanation, 1):
        arrow = "↑" if feat['direction'] == 'increase' else "↓"
        print(f"  {i}. {feat['description']}")
        print(f"     Feature: {feat['feature']}")
        print(f"     Value: {feat['value']}")
        print(f"     Impact: {arrow} {feat['percentage']}% ({feat['shap_value']:+.4f})")
        print()