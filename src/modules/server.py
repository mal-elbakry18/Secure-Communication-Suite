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


from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
import socket
import threading
import queue
import os
import time

print("All imports are successful!")

USERS = {}
CLIENTS = {}  # Map usernames to client sockets
input_queue = queue.Queue()
output_queue = queue.Queue()

def generate_rsa_keys(username):
    """Generate RSA key pair for the user and save them."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Save the keys to the USERS dictionary
    USERS[username] = {"private_key": private_key, "public_key": public_key}

    return private_key, public_key


def challenge_response(client, username):
    public_key = RSA.import_key(USERS[username]["public_key"])
    challenge = get_random_bytes(16)
    client.send(challenge)
    response = client.recv(256)

    h = SHA256.new(challenge)
    try:
        pkcs1_15.new(public_key).verify(h, response)
        client.send("AUTH_SUCCESS".encode())
        return True
    except (ValueError, TypeError):
        client.send("AUTH_FAILED".encode())
        return False

def session_key_exchange(client, username):
    private_key = RSA.import_key(USERS[username]["private_key"])
    aes_key = get_random_bytes(32)
    client_public_key = RSA.import_key(client.recv(2048))

    cipher_rsa = PKCS1_OAEP.new(client_public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    client.send(encrypted_key)

    return aes_key

USERS = {}
CLIENTS = {}  # Map usernames to client sockets
MESSAGE_QUEUES = {}  # Store undelivered messages for each user


def handle_client(client):
    try:
        username = client.recv(1024).decode()

        if username not in USERS:
            client.send("SIGN_UP".encode())
            private_key, public_key = generate_rsa_keys(username)
            USERS[username] = {"private_key": private_key, "public_key": public_key}
            MESSAGE_QUEUES[username] = queue.Queue()
            print(f"{username} registered successfully.")
        else:
            client.send("SIGN_IN".encode())
            if not challenge_response(client, username):
                print(f"Authentication failed for {username}.")
                client.close()
                return

        CLIENTS[username] = client
        print(f"{username} connected to the server.")

        while True:
            try:
                data_type = client.recv(1024).decode()
                if data_type == "MESSAGE":
                    recipient = client.recv(1024).decode().strip()  # Receive recipient username
                    message = client.recv(2048).decode().strip()   # Receive message content

                    print(f"Message from {username} to {recipient}: {message}")

                    if recipient in CLIENTS:
                        recipient_client = CLIENTS[recipient]
                        recipient_client.send(f"From {username}: {message}".encode())
                        print(f"Message delivered to {recipient}.")
                    else:
                        if recipient in MESSAGE_QUEUES:
                            MESSAGE_QUEUES[recipient].put(f"From {username}: {message}")
                            client.send(f"User {recipient} is not connected. Message stored.".encode())
                            print(f"Message stored for {recipient}.")
                        else:
                            client.send(f"User {recipient} does not exist.".encode())
                            print(f"Message from {username} could not be delivered: {recipient} does not exist.")
                elif data_type == "RECEIVE":
                    print(f"User {username} requested their messages.")
                    if username in MESSAGE_QUEUES:
                        while not MESSAGE_QUEUES[username].empty():
                            queued_message = MESSAGE_QUEUES[username].get()
                            client.send(queued_message.encode())
                            print(f"Delivered queued message to {username}: {queued_message}")
                    client.send("END_OF_MESSAGES".encode())  # Signal end of messages
                elif data_type == "EXIT":
                    print(f"{username} disconnected.")
                    del CLIENTS[username]
                    client.close()
                    break
            except ConnectionResetError:
                print(f"Connection with {username} was reset.")
                break
    except Exception as e:
        print(f"Error handling {username}: {e}")
        client.close()




def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 5566))
    server.listen(5)
    print("Server is running on port 5566...")

    while True:
        client, _ = server.accept()
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == "__main__":
    start_server()
