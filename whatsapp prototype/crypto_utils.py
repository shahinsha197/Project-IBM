# crypto_utils.py
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import os
import base64

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 16-byte AES key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password.encode())

def encrypt_data_gcm(plaintext: str, key_bytes: bytes) -> tuple:
    """Encrypts data using AES-128-GCM."""
    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(12)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return nonce, ciphertext_with_tag

def decrypt_data_gcm(nonce: bytes, ciphertext_with_tag: bytes, key_bytes: bytes) -> str:
    """Decrypts data using AES-128-GCM."""
    aesgcm = AESGCM(key_bytes)
    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        return decrypted_bytes.decode('utf-8')
    except InvalidTag:
        raise ValueError("Decryption failed: Invalid tag or key")

# --- New utility functions for web handling ---
def encrypt_message_for_web(plaintext: str, password: str) -> dict:
    """Encrypts a message and returns components for web transmission."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce, ciphertext_with_tag = encrypt_data_gcm(plaintext, key)
    
    return {
        "salt": base64.b64encode(salt).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext_with_tag).decode('utf-8')
    }

def decrypt_message_from_web(salt_b64: str, nonce_b64: str, ciphertext_b64: str, password: str) -> str:
    """Decrypts a message from web-transmitted components."""
    try:
        salt = base64.b64decode(salt_b64)
        nonce = base64.b64decode(nonce_b64)
        ciphertext_with_tag = base64.b64decode(ciphertext_b64)
        
        key = derive_key(password, salt)
        return decrypt_data_gcm(nonce, ciphertext_with_tag, key)
    except (ValueError, Exception) as e:
        raise ValueError(f"Decryption failed: {e}")