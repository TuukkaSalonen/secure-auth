from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives import padding

# Encrypts file data using AES-256 encryption with user specific key
def encrypt_file(file_bytes, user):
    user_key = user.decrypt_user_key()
    
    # Generate AES key and IVs
    aes_key = os.urandom(32)
    iv_file = os.urandom(16)
    iv_key = os.urandom(16)

    # Pad data to 128-bit block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_bytes) + padder.finalize()

    # Encrypt data
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv_file))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Encrypt AES key using user-specific key
    cipher_key = Cipher(algorithms.AES(user_key), modes.CBC(iv_key))
    key_encryptor = cipher_key.encryptor()
    encrypted_aes_key = key_encryptor.update(aes_key) + key_encryptor.finalize()

    return encrypted_data, encrypted_aes_key, iv_file, iv_key

# Decrypts file data using AES-256 decryption with user specific key
def decrypt_file(encrypted_data, encrypted_key, iv_file, iv_key, user):
    user_key = user.decrypt_user_key()

    # Decrypt key
    cipher_key = Cipher(algorithms.AES(user_key), modes.CBC(iv_key))
    key_decryptor = cipher_key.decryptor()
    aes_key = key_decryptor.update(encrypted_key) + key_decryptor.finalize()

    # Decrypt data
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv_file))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data