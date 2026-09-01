import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Key Management ─────────────────────────────────────────
KEY_FILE = 'encryption/master.key'

def get_or_create_key():
    """
    Get the master encryption key.
    If it doesn't exist, generate a new 256-bit (32 bytes) key.
    In production, this key would be stored in AWS KMS or HSM.
    """
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = AESGCM.generate_key(bit_length=256)
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        print("[+] New AES-256 master key generated")
        return key

# ── Encryption ─────────────────────────────────────────────
def encrypt_data(plaintext: str) -> str:
    """
    Encrypt data using AES-256-GCM.
    Returns base64-encoded string containing IV + ciphertext + tag.
    """
    if not plaintext:
        return ""
    
    key = get_or_create_key()
    aesgcm = AESGCM(key)
    
    # Generate a unique 96-bit IV (nonce) for every encryption
    iv = os.urandom(12)
    
    # Encrypt (returns ciphertext + auth tag combined)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)
    
    # Combine IV + ciphertext for storage
    encrypted_blob = iv + ciphertext
    
    # Return as base64 string for DB storage
    return base64.b64encode(encrypted_blob).decode('utf-8')

# ── Decryption ─────────────────────────────────────────────
def decrypt_data(encrypted_b64: str) -> str:
    """
    Decrypt data encrypted with encrypt_data().
    Returns the original plaintext string.
    Raises exception if data is tampered with.
    """
    if not encrypted_b64:
        return ""
    
    try:
        key = get_or_create_key()
        aesgcm = AESGCM(key)
        
        # Decode from base64
        encrypted_blob = base64.b64decode(encrypted_b64)
        
        # Extract IV (first 12 bytes) and ciphertext (rest)
        iv = encrypted_blob[:12]
        ciphertext = encrypted_blob[12:]
        
        # Decrypt (automatically verifies the auth tag)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        return plaintext.decode('utf-8')
    
    except Exception as e:
        return f"[DECRYPTION FAILED: {str(e)}]"

# ── Test ───────────────────────────────────────────────────
if __name__ == '__main__':
    # Quick self-test
    original = "This is a secret message!"
    encrypted = encrypt_data(original)
    decrypted = decrypt_data(encrypted)
    
    print(f"Original:  {original}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {original == decrypted}")