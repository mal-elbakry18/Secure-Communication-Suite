#RSA IMPLEMENTATION
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_session_key(public_key, session_key):
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    return cipher_rsa.encrypt(session_key)

def decrypt_session_key(private_key, encrypted_key):
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    return cipher_rsa.decrypt(encrypted_key)
