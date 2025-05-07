import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..config import Config
import os

# Load encryption key for MFA secret and master key from env
key_MFA = Config.ENCRYPTION_KEY_MFA
master_key = Config.MASTER_KEY

if not key_MFA or not master_key:
    raise ValueError("No encryption keys found")

cipher_suite_MFA = Fernet(key_MFA)

# Encrypt MFA secret 
def encrypt_secret_MFA(secret):
    return cipher_suite_MFA.encrypt(secret.encode()).decode()

# Decrypt MFA secret
def decrypt_secret_MFA(encrypted_secret):
    return cipher_suite_MFA.decrypt(encrypted_secret.encode()).decode()

# Get the master key and decode it
def get_master_key():
    return base64.urlsafe_b64decode(master_key)

# Encrypt user-specific key with the master key
def generate_user_key():
    user_key = os.urandom(32)  # Generate a random user key
    key = get_master_key()
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    encrypted = aesgcm.encrypt(iv, user_key, None) 

    return encrypted, iv

# Decrypt user-specific key with the master key
def decrypt_user_key(encrypted_user_key, iv):
    key = get_master_key()
    aesgcm = AESGCM(key)
    decrypted = aesgcm.decrypt(iv, encrypted_user_key, None)

    return decrypted