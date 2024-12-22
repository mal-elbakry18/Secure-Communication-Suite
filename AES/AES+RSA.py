from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend


import os
import base64

# Generate RSA key pair
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt AES key using RSA public key
def rsa_encrypt_key(aes_key: bytes, public_key) -> bytes:
    encrypted_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return encrypted_key

# Decrypt AES key using RSA private key
def rsa_decrypt_key(encrypted_key: bytes, private_key) -> bytes:
    aes_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return aes_key

# Function to encrypt data
def encrypt(data: str, aes_key: bytes) -> (bytes, bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the data to be AES block size compatible
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext, iv

# Function to decrypt data
def decrypt(ciphertext: bytes, iv: bytes, aes_key: bytes) -> str:
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt and unpad the data
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

# Example usage
def main():
    data = "Secure communication is critical!"

    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Generate AES key
    aes_key = os.urandom(32)

    # Encrypt AES key with RSA public key
    encrypted_aes_key = rsa_encrypt_key(aes_key, public_key)

    # Encrypt the data using AES
    ciphertext, iv = encrypt(data, aes_key)
    print(f"Ciphertext (Base64): {base64.b64encode(ciphertext).decode()}")
    print(f"IV (Base64): {base64.b64encode(iv).decode()}")
    print(f"Encrypted AES Key (Base64): {base64.b64encode(encrypted_aes_key).decode()}")

    # Decrypt AES key with RSA private key
    decrypted_aes_key = rsa_decrypt_key(encrypted_aes_key, private_key)

    # Decrypt the data using AES
    decrypted_data = decrypt(ciphertext, iv, decrypted_aes_key)
    print(f"Decrypted Data: {decrypted_data}")

if __name__ == "__main__":
    main()
