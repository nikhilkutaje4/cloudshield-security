"""
Adaptive Cryptography Engine
─────────────────────────────
ML-driven encryption selection based on:
  - Data sensitivity (category)
  - Current threat level (from IDS)
  - Data size
  - User behavior context

Algorithms supported:
  🟢 AES-128-GCM   → Low risk, general data
  🟡 AES-256-GCM   → Medium risk, passwords
  🟠 ECC (P-384)   → High risk, financial data
  🔴 Kyber-512     → Critical risk, post-quantum resistant
"""

import os
import base64
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# Try Kyber (post-quantum). Fallback if unavailable.
try:
    from kyber_py.ml_kem import ML_KEM_512
    KYBER_AVAILABLE = True
except ImportError:
    KYBER_AVAILABLE = False

# ── Sensitivity Levels ─────────────────────────────────────
SENSITIVITY_MAP = {
    'General':     1,   # Notes, misc
    'Note':        1,
    'Password':    2,   # Login credentials
    'API Key':     3,   # Service tokens
    'Credit Card': 4,   # Financial
}

# ── Algorithm Registry ─────────────────────────────────────
ALGORITHMS = {
    'AES-128-GCM': {
        'name': 'AES-128-GCM',
        'strength': 'Standard',
        'color': '#22c55e',
        'icon': '🟢',
        'description': 'Symmetric encryption, 128-bit key',
        'use_case': 'General purpose data'
    },
    'AES-256-GCM': {
        'name': 'AES-256-GCM',
        'strength': 'Strong',
        'color': '#3b82f6',
        'icon': '🔵',
        'description': 'Symmetric encryption, 256-bit key',
        'use_case': 'Sensitive credentials'
    },
    'ECC-P384': {
        'name': 'ECC (Curve P-384)',
        'strength': 'High',
        'color': '#f59e0b',
        'icon': '🟠',
        'description': 'Elliptic Curve Cryptography',
        'use_case': 'Financial & high-value data'
    },
    'Kyber-512': {
        'name': 'Kyber-512 (Post-Quantum)',
        'strength': 'Quantum-Safe',
        'color': '#ef4444',
        'icon': '🔴',
        'description': 'NIST post-quantum standard',
        'use_case': 'Critical data, quantum-resistant'
    }
}

# ═══════════════════════════════════════════════════════════
#  ML-BASED ALGORITHM SELECTOR
# ═══════════════════════════════════════════════════════════

def select_algorithm(category='General', threat_level='Normal', 
                     data_size=0, recent_threats=0):
    """
    Intelligently select encryption algorithm based on context.
    
    This is a rule-based ML decision engine (like a Decision Tree).
    In production, this could be replaced with a trained classifier.
    """
    # Base score from data sensitivity
    sensitivity = SENSITIVITY_MAP.get(category, 1)
    risk_score = sensitivity * 10
    
    # Add points based on IDS threat level
    threat_bonus = {
        'Normal': 0,
        'Low': 15,
        'High': 30
    }
    risk_score += threat_bonus.get(threat_level, 0)
    
    # Recent threat activity increases risk
    if recent_threats > 5:
        risk_score += 20
    elif recent_threats > 2:
        risk_score += 10
    
    # Large data may warrant stronger encryption
    if data_size > 1000:
        risk_score += 5
    
    # ── Decision Tree ──
    if risk_score >= 60 and KYBER_AVAILABLE:
        chosen = 'Kyber-512'
        reason = f"Critical risk score ({risk_score}) — using post-quantum encryption"
    elif risk_score >= 40:
        chosen = 'ECC-P384'
        reason = f"High risk score ({risk_score}) — using elliptic curve cryptography"
    elif risk_score >= 20:
        chosen = 'AES-256-GCM'
        reason = f"Medium risk score ({risk_score}) — using strong AES-256"
    else:
        chosen = 'AES-128-GCM'
        reason = f"Low risk score ({risk_score}) — standard AES-128 sufficient"
    
    return {
        'algorithm': chosen,
        'risk_score': risk_score,
        'reason': reason,
        'sensitivity': sensitivity,
        'threat_level': threat_level,
        'info': ALGORITHMS[chosen]
    }

# ═══════════════════════════════════════════════════════════
#  KEY STORAGE
# ═══════════════════════════════════════════════════════════

KEY_DIR = 'encryption/keys'
os.makedirs(KEY_DIR, exist_ok=True)

def _get_aes_key(bits=256):
    """Get or generate an AES key of given size"""
    filename = f'{KEY_DIR}/aes_{bits}.key'
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            return f.read()
    key = get_random_bytes(bits // 8)
    with open(filename, 'wb') as f:
        f.write(key)
    return key

def _get_ecc_keys():
    """Get or generate ECC key pair (P-384)"""
    priv_file = f'{KEY_DIR}/ecc_private.pem'
    pub_file = f'{KEY_DIR}/ecc_public.pem'
    
    if os.path.exists(priv_file):
        with open(priv_file, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        return private_key, private_key.public_key()
    
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    
    # Save
    with open(priv_file, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(pub_file, 'wb') as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return private_key, private_key.public_key()

def _get_kyber_keys():
    """Get or generate Kyber-512 key pair"""
    priv_file = f'{KEY_DIR}/kyber_private.bin'
    pub_file = f'{KEY_DIR}/kyber_public.bin'
    
    if os.path.exists(priv_file):
        with open(priv_file, 'rb') as f:
            secret_key = f.read()
        with open(pub_file, 'rb') as f:
            public_key = f.read()
        return public_key, secret_key
    
    public_key, secret_key = ML_KEM_512.keygen()
    with open(priv_file, 'wb') as f:
        f.write(secret_key)
    with open(pub_file, 'wb') as f:
        f.write(public_key)
    return public_key, secret_key

# ═══════════════════════════════════════════════════════════
#  ENCRYPTION IMPLEMENTATIONS
# ═══════════════════════════════════════════════════════════

def _aes_encrypt(plaintext: str, bits: int) -> str:
    """AES-GCM encryption (128 or 256 bit)"""
    key = _get_aes_key(bits)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    blob = nonce + tag + ciphertext
    return base64.b64encode(blob).decode('utf-8')

def _aes_decrypt(encrypted_b64: str, bits: int) -> str:
    """AES-GCM decryption"""
    key = _get_aes_key(bits)
    blob = base64.b64decode(encrypted_b64)
    nonce, tag, ciphertext = blob[:12], blob[12:28], blob[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

def _ecc_encrypt(plaintext: str) -> str:
    """
    ECC encryption using ECIES scheme:
      1. Generate ephemeral key pair
      2. Derive shared secret using ECDH with recipient's public key
      3. Derive AES key from shared secret using HKDF
      4. Encrypt with AES-GCM
    """
    _, recipient_public = _get_ecc_keys()
    
    # Ephemeral key pair
    ephemeral_private = ec.generate_private_key(ec.SECP384R1(), default_backend())
    ephemeral_public = ephemeral_private.public_key()
    
    # ECDH shared secret
    shared_key = ephemeral_private.exchange(ec.ECDH(), recipient_public)
    
    # Derive AES key
    derived_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b'CloudShield-ECC', backend=default_backend()
    ).derive(shared_key)
    
    # Encrypt with AES-GCM
    nonce = get_random_bytes(12)
    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    
    # Serialize ephemeral public key
    ephemeral_pub_bytes = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Combine: [pub_len(2)] [ephemeral_pub] [nonce(12)] [tag(16)] [ciphertext]
    pub_len = len(ephemeral_pub_bytes).to_bytes(2, 'big')
    blob = pub_len + ephemeral_pub_bytes + nonce + tag + ciphertext
    return base64.b64encode(blob).decode('utf-8')

def _ecc_decrypt(encrypted_b64: str) -> str:
    """Reverse the ECIES encryption"""
    recipient_private, _ = _get_ecc_keys()
    blob = base64.b64decode(encrypted_b64)
    
    pub_len = int.from_bytes(blob[:2], 'big')
    ephemeral_pub_bytes = blob[2:2 + pub_len]
    rest = blob[2 + pub_len:]
    nonce, tag, ciphertext = rest[:12], rest[12:28], rest[28:]
    
    ephemeral_public = serialization.load_der_public_key(
        ephemeral_pub_bytes, backend=default_backend()
    )
    
    shared_key = recipient_private.exchange(ec.ECDH(), ephemeral_public)
    derived_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b'CloudShield-ECC', backend=default_backend()
    ).derive(shared_key)
    
    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

def _kyber_encrypt(plaintext: str) -> str:
    """
    Kyber-512 hybrid encryption:
      1. Kyber KEM generates shared secret
      2. Use shared secret as AES key
      3. Encrypt plaintext with AES-GCM
    """
    public_key, _ = _get_kyber_keys()
    
    # Encapsulate to get shared secret
    shared_secret, kem_ciphertext = ML_KEM_512.encaps(public_key)
    
    # Use first 32 bytes of shared secret as AES-256 key
    aes_key = shared_secret[:32]
    nonce = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    
    # Combine: [kem_len(2)] [kem_ciphertext] [nonce(12)] [tag(16)] [ciphertext]
    kem_len = len(kem_ciphertext).to_bytes(2, 'big')
    blob = kem_len + kem_ciphertext + nonce + tag + ciphertext
    return base64.b64encode(blob).decode('utf-8')

def _kyber_decrypt(encrypted_b64: str) -> str:
    """Reverse Kyber hybrid encryption"""
    _, secret_key = _get_kyber_keys()
    blob = base64.b64decode(encrypted_b64)
    
    kem_len = int.from_bytes(blob[:2], 'big')
    kem_ciphertext = blob[2:2 + kem_len]
    rest = blob[2 + kem_len:]
    nonce, tag, ciphertext = rest[:12], rest[12:28], rest[28:]
    
    shared_secret = ML_KEM_512.decaps(secret_key, kem_ciphertext)
    aes_key = shared_secret[:32]
    
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

# ═══════════════════════════════════════════════════════════
#  UNIFIED ENCRYPT / DECRYPT
# ═══════════════════════════════════════════════════════════

def adaptive_encrypt(plaintext: str, algorithm: str) -> str:
    """Encrypt using the specified algorithm"""
    if algorithm == 'AES-128-GCM':
        return _aes_encrypt(plaintext, 128)
    elif algorithm == 'AES-256-GCM':
        return _aes_encrypt(plaintext, 256)
    elif algorithm == 'ECC-P384':
        return _ecc_encrypt(plaintext)
    elif algorithm == 'Kyber-512':
        return _kyber_encrypt(plaintext)
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")

def adaptive_decrypt(encrypted_b64: str, algorithm: str) -> str:
    """Decrypt using the specified algorithm"""
    try:
        if algorithm == 'AES-128-GCM':
            return _aes_decrypt(encrypted_b64, 128)
        elif algorithm == 'AES-256-GCM':
            return _aes_decrypt(encrypted_b64, 256)
        elif algorithm == 'ECC-P384':
            return _ecc_decrypt(encrypted_b64)
        elif algorithm == 'Kyber-512':
            return _kyber_decrypt(encrypted_b64)
        else:
            return f"[Unknown algorithm: {algorithm}]"
    except Exception as e:
        return f"[Decryption failed: {str(e)}]"

# ═══════════════════════════════════════════════════════════
#  SELF TEST
# ═══════════════════════════════════════════════════════════

if __name__ == '__main__':
    test_cases = [
        ('General', 'Normal', 0, "My grocery list"),
        ('Password', 'Normal', 0, "MyP@ssw0rd123"),
        ('API Key', 'Low', 2, "sk_live_abc123xyz"),
        ('Credit Card', 'High', 6, "4532-1234-5678-9010"),
    ]
    
    print(f"\n{'═'*70}")
    print(f"  CloudShield Adaptive Cryptography Engine — Self Test")
    print(f"{'═'*70}\n")
    
    print(f"Kyber Available: {KYBER_AVAILABLE}\n")
    
    for category, threat, recent, secret in test_cases:
        decision = select_algorithm(category, threat, len(secret), recent)
        encrypted = adaptive_encrypt(secret, decision['algorithm'])
        decrypted = adaptive_decrypt(encrypted, decision['algorithm'])
        match = "✅" if decrypted == secret else "❌"
        
        print(f"[{category}] Threat: {threat} | Recent: {recent}")
        print(f"  → Algorithm: {decision['info']['icon']} {decision['algorithm']}")
        print(f"  → Reason: {decision['reason']}")
        print(f"  → Encrypted: {encrypted[:60]}...")
        print(f"  → {match} Decrypted: {decrypted}\n")