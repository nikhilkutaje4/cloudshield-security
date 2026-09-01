import hashlib
import secrets

def generate_fingerprint_hash(username):
    """
    Simulate fingerprint enrollment.
    In real systems, this would be biometric data.
    We generate a unique hash tied to the user.
    """
    unique_token = secrets.token_hex(16)
    fingerprint_data = f"{username}:{unique_token}"
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()

def verify_fingerprint(stored_hash, scanned_hash):
    """Verify the scanned fingerprint matches the stored one"""
    if not stored_hash or not scanned_hash:
        return False
    return stored_hash == scanned_hash