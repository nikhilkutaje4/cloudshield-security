"""
Autoencoder Anomaly Detector — Prediction Module
─────────────────────────────────────────────────
Uses the trained autoencoder to detect anomalies via reconstruction error.
"""

import joblib
import numpy as np
import pandas as pd
import os
import warnings
warnings.filterwarnings('ignore')

# ── Global cache ───────────────────────────────────────────
_ae_model = None
_ae_scaler = None
_ae_encoders = None
_ae_feature_names = None
_ae_metadata = None

def load_autoencoder():
    """Load autoencoder model into memory"""
    global _ae_model, _ae_scaler, _ae_encoders, _ae_feature_names, _ae_metadata
    
    if _ae_model is None:
        print("[i] Loading Autoencoder model...")
        _ae_model = joblib.load('models/autoencoder.pkl')
        _ae_scaler = joblib.load('models/ae_scaler.pkl')
        _ae_encoders = joblib.load('models/ae_encoders.pkl')
        _ae_feature_names = joblib.load('models/ae_feature_names.pkl')
        _ae_metadata = joblib.load('models/ae_metadata.pkl')
        acc = _ae_metadata['overall_accuracy'] * 100
        print(f"[✓] Autoencoder loaded. Accuracy: {acc:.2f}%")
    
    return _ae_model, _ae_scaler, _ae_encoders, _ae_feature_names, _ae_metadata

def get_autoencoder_metadata():
    """Return autoencoder metadata for dashboard"""
    load_autoencoder()
    return _ae_metadata

def detect_anomaly(features_dict):
    """
    Detect anomaly using reconstruction error.
    Returns dict with anomaly score and verdict.
    """
    model, scaler, encoders, feature_names, metadata = load_autoencoder()
    
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
    
    # Ensure correct column order
    df = df[feature_names]
    
    # Scale
    X_scaled = scaler.transform(df)
    
    # Reconstruct
    X_reconstructed = model.predict(X_scaled)
    
    # Calculate reconstruction error (MSE)
    error = float(np.mean(np.square(X_scaled - X_reconstructed)))
    
    threshold = metadata['threshold']
    is_anomaly = error > threshold
    
    # How much above threshold (severity)
    if is_anomaly:
        severity_ratio = error / threshold
        if severity_ratio > 100:
            severity = 'Critical'
        elif severity_ratio > 10:
            severity = 'High'
        else:
            severity = 'Moderate'
    else:
        severity_ratio = error / threshold  # < 1
        severity = 'Normal'
    
    # Confidence: how confident we are in the verdict
    # Distance from threshold as % (capped at 100)
    if is_anomaly:
        confidence = min(100, (severity_ratio - 1) * 20 + 60)
    else:
        confidence = min(100, (1 - severity_ratio) * 50 + 50)
    
    return {
        'is_anomaly': is_anomaly,
        'reconstruction_error': round(error, 4),
        'threshold': round(threshold, 4),
        'severity': severity,
        'severity_ratio': round(severity_ratio, 2),
        'confidence': round(confidence, 2)
    }

# ── Ensemble: Combine RF + Autoencoder ─────────────────────
def ensemble_predict(features_dict):
    """
    Combine Random Forest + Autoencoder predictions.
    Returns a unified verdict with agreement level.
    """
    from ids.predict import predict_traffic
    
    # Get both predictions
    rf_result = predict_traffic(features_dict)
    ae_result = detect_anomaly(features_dict)
    
    # Determine agreement
    rf_thinks_attack = rf_result['is_attack']
    ae_thinks_attack = ae_result['is_anomaly']
    
    if rf_thinks_attack and ae_thinks_attack:
        agreement = 'BOTH_AGREE_ATTACK'
        verdict = 'CONFIRMED THREAT'
        verdict_icon = '🚨'
        verdict_level = 'High'
        agreement_score = 100
    elif not rf_thinks_attack and not ae_thinks_attack:
        agreement = 'BOTH_AGREE_NORMAL'
        verdict = 'TRAFFIC SAFE'
        verdict_icon = '✅'
        verdict_level = 'Normal'
        agreement_score = 100
    elif rf_thinks_attack and not ae_thinks_attack:
        agreement = 'RF_ONLY'
        verdict = 'SUSPICIOUS (RF only)'
        verdict_icon = '⚠️'
        verdict_level = 'Low'
        agreement_score = 50
    else:  # AE only
        agreement = 'AE_ONLY'
        verdict = 'ANOMALY (Autoencoder only)'
        verdict_icon = '⚠️'
        verdict_level = 'Low'
        agreement_score = 50
    
    return {
        'verdict': verdict,
        'verdict_icon': verdict_icon,
        'verdict_level': verdict_level,
        'agreement': agreement,
        'agreement_score': agreement_score,
        'rf': {
            'prediction': rf_result['prediction'],
            'is_attack': rf_result['is_attack'],
            'confidence': rf_result['confidence'],
            'description': rf_result['description']
        },
        'ae': {
            'is_anomaly': ae_result['is_anomaly'],
            'reconstruction_error': ae_result['reconstruction_error'],
            'threshold': ae_result['threshold'],
            'severity': ae_result['severity'],
            'severity_ratio': ae_result['severity_ratio'],
            'confidence': ae_result['confidence']
        }
    }

# ── Self test ──────────────────────────────────────────────
if __name__ == '__main__':
    from ids.predict import SAMPLE_TRAFFIC
    
    print(f"\n{'═' * 70}")
    print(f"  Ensemble Detection Test (Random Forest + Autoencoder)")
    print(f"{'═' * 70}\n")
    
    for name, features in SAMPLE_TRAFFIC.items():
        result = ensemble_predict(features)
        
        print(f"── {name} ─────────────────────────────")
        print(f"  {result['verdict_icon']} Verdict: {result['verdict']}")
        print(f"  Agreement: {result['agreement']} ({result['agreement_score']}%)")
        print(f"  ")
        print(f"  🌲 Random Forest: {result['rf']['prediction']} "
              f"({result['rf']['confidence']}%)")
        print(f"  🧠 Autoencoder:   {'ANOMALY' if result['ae']['is_anomaly'] else 'NORMAL'} "
              f"| Error: {result['ae']['reconstruction_error']} "
              f"| Threshold: {result['ae']['threshold']}")
        print(f"     Severity: {result['ae']['severity']} "
              f"({result['ae']['severity_ratio']}x threshold)")
        print()