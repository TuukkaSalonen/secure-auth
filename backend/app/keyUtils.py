import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from .config import Config
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
def encrypt_user_key(user_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(get_master_key()), modes.CBC(iv))
    encryptor = cipher.encryptor()

    encrypted_user_key = encryptor.update(user_key) + encryptor.finalize()

    return encrypted_user_key, iv

# Decrypt user-specific key with the master key
def decrypt_user_key(encrypted_user_key, iv):
    cipher = Cipher(algorithms.AES(get_master_key()), modes.CBC(iv))
    decryptor = cipher.decryptor()

    decrypted_user_key = decryptor.update(encrypted_user_key) + decryptor.finalize()

    return decrypted_user_key