#AES IMPLEMENTATION
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

class AESHandler:
    def __init__(self):
        self.key = get_random_bytes(16)  # AES key

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

    def decrypt(self, enc_text):
        enc_data = base64.b64decode(enc_text.encode())
        nonce = enc_data[:16]
        tag = enc_data[16:32]
        ciphertext = enc_data[32:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
