from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from .config import Config

kek = Config.MASTER_KEY # The Master Encryption Key

# Encrypts file data using AES encryption with user specific key
def encrypt_file(file_bytes, user):
    user_key = user.decrypt_user_key()  # Decrypt user-specific key
    
    # Generate AES key and IV
    aes_key = os.urandom(32)  # AES-256 key (32 bytes)
    iv = os.urandom(16)       # 128-bit IV for CBC mode
    
    # Pad file data to 16 bytes (AES block size)
    padded_data = file_bytes + b"\0" * (16 - len(file_bytes) % 16)

    # Encrypt file data
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Encrypt the AES key using the user's encryption key
    cipher_key = Cipher(algorithms.AES(user_key), modes.CBC(iv))  # Use user-specific key for AES
    key_encryptor = cipher_key.encryptor()
    encrypted_aes_key = key_encryptor.update(aes_key) + key_encryptor.finalize()

    return encrypted_data, encrypted_aes_key, iv


# Decrypts file data using AES decryption with user specific key
def decrypt_file(encrypted_data, encrypted_key, iv, user):
    user_key = user.decrypt_user_key()  # Decrypt user-specific key
        
    # Decrypt the AES key using the user's key
    cipher_key = Cipher(algorithms.AES(user_key), modes.CBC(iv))
    key_decryptor = cipher_key.decryptor()
    aes_key = key_decryptor.update(encrypted_key) + key_decryptor.finalize()

    # Decrypt the file data using the AES key and IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding from decrypted data
    decrypted_data = decrypted_data.rstrip(b"\0")

    return decrypted_data

