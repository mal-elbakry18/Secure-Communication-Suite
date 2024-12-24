'''#ENCRYPTION WORKER
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import queue
import base64

class EncryptionWorker(threading.Thread):
    def __init__(self, plaintext_queue, ciphertext_queue):
        threading.Thread.__init__(self)
        self.plaintext_queue = plaintext_queue
        self.ciphertext_queue = ciphertext_queue
        self.key = get_random_bytes(16)  # AES key (16 bytes)

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

    def decrypt(self, enc_data):
        enc_data = base64.b64decode(enc_data)
        nonce = enc_data[:16]
        tag = enc_data[16:32]
        ciphertext = enc_data[32:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    def run(self):
        while True:
            task = self.plaintext_queue.get()
            if task is None:  # Stop the thread if None is received
                break

            task_type, data = task
            if task_type == "MESSAGE":
                encrypted_data = self.encrypt(data.encode())
            elif task_type == "FILE":
                encrypted_data = self.encrypt(data)
            else:
                encrypted_data = None

            self.ciphertext_queue.put(encrypted_data)
'''
import threading
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import queue

class EncryptionWorker(threading.Thread):
    def __init__(self, plaintext_queue, ciphertext_queue):
        threading.Thread.__init__(self)
        self.plaintext_queue = plaintext_queue
        self.ciphertext_queue = ciphertext_queue
        self.key = get_random_bytes(16)  # AES key (16 bytes)
        self.cipher = AES.new(self.key, AES.MODE_EAX)

    def run(self):
        while True:
            data = self.plaintext_queue.get()
            if data is None:  # Stop the thread when None is received
                break
            plaintext = data['message']
            username = data['username']  # Associate with the recipient's username
            nonce = self.cipher.nonce
            ciphertext, tag = self.cipher.encrypt_and_digest(plaintext.encode())
            self.ciphertext_queue.put({
                "username": username,
                "ciphertext": ciphertext,
                "tag": tag,
                "nonce": nonce
            })

    def decrypt(self, encrypted_data):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=encrypted_data["nonce"])
        plaintext = cipher.decrypt_and_verify(encrypted_data["ciphertext"], encrypted_data["tag"])
        return plaintext.decode()
