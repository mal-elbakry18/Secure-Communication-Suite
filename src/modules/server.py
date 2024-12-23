'''#SERVER CODE IMPLEMENTATION
import socket
import queue
from encryption_worker import EncryptionWorker

def handle_message(client, plaintext_queue, ciphertext_queue):
    # Receive message content
    message = client.recv(1024).decode()
    print("Received message:", message)

    # Encrypt the message
    plaintext_queue.put(("MESSAGE", message))
    encrypted_data = ciphertext_queue.get()

    # Send the encrypted message
    client.send(encrypted_data.encode())
    print("Sent encrypted message")

def handle_file(client, plaintext_queue, ciphertext_queue):
    # Receive file name and size
    file_name = client.recv(1024).decode()
    file_size = int(client.recv(1024).decode())
    print(f"Receiving file '{file_name}' of size {file_size} bytes")

    # Receive file content
    file_data = b""
    while file_size > 0:
        chunk = client.recv(1024)
        file_data += chunk
        file_size -= len(chunk)

    # Encrypt the file data
    plaintext_queue.put(("FILE", file_data))
    encrypted_data = ciphertext_queue.get()

    # Send encrypted file data
    client.send(encrypted_data.encode())
    print(f"Encrypted file '{file_name}' sent to client")

def start_server():
    # Create queues for communication
    plaintext_queue = queue.Queue()
    ciphertext_queue = queue.Queue()

    # Start encryption worker
    worker = EncryptionWorker(plaintext_queue, ciphertext_queue)
    worker.start()

    # Start server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 5000))
    server.listen(5)
    print("Server listening on port 5000")

    while True:
        client, address = server.accept()
        print(f"Connection from {address}")

        # Receive content type
        content_type = client.recv(1024).decode()
        if content_type == "MESSAGE":
            handle_message(client, plaintext_queue, ciphertext_queue)
        elif content_type == "FILE":
            handle_file(client, plaintext_queue, ciphertext_queue)
        else:
            print("Unknown content type received")

        client.close()

    # Stop the worker thread
    plaintext_queue.put(None)
    worker.join()
'''
'''from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os
import socket
import threading
import time

# Store user data (username: {private_key, public_key})
USERS = {}

def generate_rsa_keys(username):
    """Generate RSA key pair for the user and save them."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    USERS[username] = {"private_key": private_key, "public_key": public_key}
    return private_key, public_key

def send_user_keys(client, username):
    """Send generated keys to the user for copying."""
    private_key, public_key = USERS[username]["private_key"], USERS[username]["public_key"]
    client.send("Your private key (keep it safe):\n".encode() + private_key)
    client.send("\nYour public key:\n".encode() + public_key)
    time.sleep(5)  # Allow user to copy keys
    client.send("\nKeys are no longer available.".encode())

def challenge_response(client, username):
    """Challenge-response mechanism for authentication."""
    public_key = RSA.import_key(USERS[username]["public_key"])

    # Generate and send challenge
    challenge = get_random_bytes(16)
    client.send(challenge)
    response = client.recv(256)

    # Verify response
    h = SHA256.new(challenge)
    try:
        pkcs1_15.new(public_key).verify(h, response)
        client.send("AUTH_SUCCESS".encode())
        return True
    except (ValueError, TypeError):
        client.send("AUTH_FAILED".encode())
        return False

def session_key_exchange(client, username):
    """Securely exchange an AES session key using RSA."""
    private_key = RSA.import_key(USERS[username]["private_key"])
    aes_key = get_random_bytes(32)
    client_public_key = RSA.import_key(client.recv(2048))

    # Encrypt AES key with client's public key
    cipher_rsa = PKCS1_OAEP.new(client_public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    client.send(encrypted_key)

    return aes_key

def handle_client(client):
    """Handle client actions."""
    username = client.recv(1024).decode()
    if username not in USERS:
        client.send("SIGN_UP".encode())
        private_key, public_key = generate_rsa_keys(username)
        send_user_keys(client, username)
    else:
        client.send("SIGN_IN".encode())
        if not challenge_response(client, username):
            client.close()
            return

    aes_key = session_key_exchange(client, username)
    print(f"AES session key established with {username}.")

    client.send("READY".encode())
    while True:
        data_type = client.recv(1024).decode()
        if data_type == "MESSAGE":
            message = client.recv(2048)
            print(f"Encrypted message from {username}: {message}")
        elif data_type == "FILE":
            file_name = client.recv(1024).decode()
            file_size = int(client.recv(1024).decode())
            with open(f"received_{file_name}", "wb") as file:
                while file_size > 0:
                    chunk = client.recv(1024)
                    file.write(chunk)
                    file_size -= len(chunk)
            print(f"File {file_name} received from {username}.")
        else:
            break

def start_server():
    """Start the server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 5000))
    server.listen(5)
    print("Server is running...")

    while True:
        client, _ = server.accept()
        threading.Thread(target=handle_client, args=(client,)).start()
'''
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import socket
import threading
import queue
import os
import time
#from modules.encryption_worker import EncryptionWorker
from .encryption_worker import EncryptionWorker


# Store user data (username: {private_key, public_key})
USERS = {}

# Queues for encryption and decryption
input_queue = queue.Queue()
output_queue = queue.Queue()

# Encryption worker
worker = EncryptionWorker(input_queue, output_queue)
worker.start()

def generate_rsa_keys(username):
    """Generate RSA key pair for the user and save them."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    USERS[username] = {"private_key": private_key, "public_key": public_key}
    return private_key, public_key

def send_user_keys(client, username):
    """Send generated keys to the user for copying."""
    private_key, public_key = USERS[username]["private_key"], USERS[username]["public_key"]
    client.send("Your private key (keep it safe):\n".encode() + private_key)
    client.send("\nYour public key:\n".encode() + public_key)
    time.sleep(5)  # Allow user to copy keys
    client.send("\nKeys are no longer available.".encode())

def challenge_response(client, username):
    """Challenge-response mechanism for authentication."""
    public_key = RSA.import_key(USERS[username]["public_key"])

    # Generate and send challenge
    challenge = get_random_bytes(16)
    client.send(challenge)
    response = client.recv(256)

    # Verify response
    h = SHA256.new(challenge)
    try:
        pkcs1_15.new(public_key).verify(h, response)
        client.send("AUTH_SUCCESS".encode())
        return True
    except (ValueError, TypeError):
        client.send("AUTH_FAILED".encode())
        return False

def session_key_exchange(client, username):
    """Securely exchange an AES session key using RSA."""
    private_key = RSA.import_key(USERS[username]["private_key"])
    aes_key = get_random_bytes(32)
    client_public_key = RSA.import_key(client.recv(2048))

    # Encrypt AES key with client's public key
    cipher_rsa = PKCS1_OAEP.new(client_public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    client.send(encrypted_key)

    return aes_key

def handle_client(client):
    """Handle client actions."""
    username = client.recv(1024).decode()
    if username not in USERS:
        client.send("SIGN_UP".encode())
        private_key, public_key = generate_rsa_keys(username)
        send_user_keys(client, username)
    else:
        client.send("SIGN_IN".encode())
        if not challenge_response(client, username):
            client.close()
            return

    aes_key = session_key_exchange(client, username)
    print(f"AES session key established with {username}.")
    client.send("READY".encode())

    while True:
        data_type = client.recv(1024).decode()
        if data_type == "MESSAGE":
            message = client.recv(2048)
            input_queue.put(("decrypt", message.encode()))  # Decrypt the message
            decrypted_message = output_queue.get()
            print(f"Decrypted message from {username}: {decrypted_message.decode()}")
        elif data_type == "FILE":
            file_name = client.recv(1024).decode()
            file_size = int(client.recv(1024).decode())
            with open(f"received_{file_name}", "wb") as file:
                while file_size > 0:
                    chunk = client.recv(1024)
                    file.write(chunk)
                    file_size -= len(chunk)
            print(f"File {file_name} received from {username}.")
        else:
            break

def start_server():
    """Start the server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 5001))
    server.listen(5)
    print("Server is running...")

    while True:
        client, _ = server.accept()
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == "__main__":
    start_server()