from cryptography.fernet import Fernet
from .config import Config

# Load encryption key for MFA secret from env
key_MFA = Config.ENCRYPTION_KEY_MFA

if not key_MFA:
    raise ValueError("No encryption keys found")

cipher_suite_MFA = Fernet(key_MFA)

# Encrypt MFA secret 
def encrypt_secret_MFA(secret):
    return cipher_suite_MFA.encrypt(secret.encode()).decode()

# Decrypt MFA secret
def decrypt_secret_MFA(encrypted_secret):
    return cipher_suite_MFA.decrypt(encrypted_secret.encode()).decode()