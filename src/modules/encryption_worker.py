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
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import queue

class EncryptionWorker(threading.Thread):
    def __init__(self, input_queue, output_queue):
        threading.Thread.__init__(self)
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.key = get_random_bytes(32)  # AES key (256-bit)
        self.daemon = True  # Daemon thread to allow clean exit

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
            task = self.input_queue.get()  # Block until a task is available
            if task is None:  # Special signal to exit the loop
                break
            action, data = task

            if action == "encrypt":
                result = self.encrypt(data)
            elif action == "decrypt":
                result = self.decrypt(data)
            else:
                result = None

            self.output_queue.put(result)  # Place the result in the output queue
            self.input_queue.task_done()
