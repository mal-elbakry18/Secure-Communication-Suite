"""from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
import socket
import threading
import queue
import os
import time

from alipay.aop.api.domain.PrintModel import PrintModel

print("Server imports successful!")

USERS = {}
CLIENTS = {}
MESSAGE_QUEUES = {}

def generate_rsa_keys(username):
    print(f"[DEBUG] Generating RSA key pair for {username}...")
    key = RSA.generate(2048)
    print("The rsa key pair has been generated!")
    print("The key pair is: ", key)
    private_key = key.export_key()
    print(f"The private key is: {private_key}")
    public_key = key.publickey().export_key()
    print(f"The public key is: {public_key}")
    USERS[username] = {"private_key": private_key, "public_key": public_key}
    print(f"The username{username} and its public key is: {USERS[username]['public_key']} "
          f"and its public key is: {USERS[username]['public_key']}")
    print(f"[DEBUG] Keys generated and stored for {username}.")
    return private_key, public_key

def challenge_response(client, username):
    print(f"[DEBUG] Starting challenge-response for {username}...")
    public_key = RSA.import_key(USERS[username]["public_key"])
    print(f"The public key fetched is: {public_key} for username {username}")
    challenge = get_random_bytes(16)
    print(f"Challenge generated for username {username} is challenge: {challenge}")
    print(f"[DEBUG] Sending challenge to {username}.")
    client.send(challenge)
    print(f"[DEBUG]Receiving challenge response from {username}.")
    response = client.recv(256)
    print(f"Response received from {username}: {response}")
    print("Hashing the challenge")
    h = SHA256.new(challenge)
    print(f"The hashing digest of the challenge: {h.hexdigest()} ")
    try:
        print("Verifying the challenge from the hashing including the public key")
        pkcs1_15.new(public_key).verify(h, response)
        print(f"[DEBUG] Challenge-response successful for {username}.")
        return True
    except (ValueError, TypeError):
        print(f"[DEBUG] Challenge-response failed for {username}.")
        return False

def session_key_exchange(client, username):
    print(f"[DEBUG] Initiating session key exchange with {username}...")
    private_key = RSA.import_key(USERS[username]["private_key"])
    print(f"The private key received is: {private_key}")
    session_key = get_random_bytes(16)
    print(f"The session key received is: {session_key}")
    cipher_rsa = PKCS1_OAEP.new(private_key)
    print(f"The cipher key received with the private key is: {cipher_rsa}")
    encrypted_key = cipher_rsa.encrypt(session_key)
    print(f"The encrypted key received is: {encrypted_key}")
    print("Sending the session key to the client encrypted with the private key .")
    client.send(encrypted_key)
    print(f"[DEBUG] Session key sent to {username}.")
    return session_key

def handle_client(client):
    try:
        print(f"[DEBUG] Handling client connection...")
        print(f"[DEBUG] Client {client} connection established.")

        username = client.recv(1024).decode().strip()
        print(f"[DEBUG] Client's username {username} connection established.")

        print(f"[DEBUG] Handling client: {username}")
        if username.lower() not in [user.lower() for user in USERS]:
            print(f"[DEBUG] Registering new user: {username}")
            client.send("SIGN_UP".encode())
            print(f"[DEBUG] New user {username} registered.")
            print("Generating rsa keys...")
            private_key, public_key = generate_rsa_keys(username)
            print(f"[DEBUG] Generated rsa key pair for {username}.")
            USERS[username] = {"private_key": private_key, "public_key": public_key}
            print(f"[DEBUG] Generated private key for {username} is {private_key}.")
            print(f"[DEBUG] Generated public key for {username} is {public_key}.")
            print("Adding The username mapped to the pair of keys in the USERS map")
            print("Generating user messaging queues...")
            MESSAGE_QUEUES[username.lower()] = queue.Queue()
            print("User messaging queues generated!")
            print(f"[DEBUG] User {username} registered successfully.")
        else:
            print(f"[DEBUG] Authenticating existing user: {username}")
            client.send("SIGN_IN".encode())
            print("Authenticating existing user by sending challenge")
            if not challenge_response(client, username):
                print(f"[DEBUG] Authentication failed for {username}. Closing connection.")
                client.close()
                return
        print("Adding username to clients map")
        CLIENTS[username] = client
        print(f"[DEBUG] {username} connected. Client socket stored.")

        while True:
            try:
                #print(f"[DEBUG] Receiving data type from {username}.")
                data_type = client.recv(1024).decode().strip()
                if data_type == "MESSAGE":
                    print(f"[DEBUG] Receiving message from {username}.")
                    data = client.recv(2048).decode().strip()
                    #print(f"[DEBUG] Received data from {username} is {data}.")
                    print(f"[DEBUG] Raw message data received: {data}")

                    try:
                        recipient, message = data.split("|", 1)
                        print(f"[DEBUG] Parsed recipient: {recipient}, message: {message}")
                    except ValueError:
                        print("[DEBUG] Invalid message format received.")
                        client.send("Error: Invalid data format.".encode())
                        continue

                    print("Message valid...")
                    print("Adding message to receiver's queue in the map...")
                    if recipient.lower() in [user.lower() for user in USERS]:
                        print("Checking if receiver is user in the system...")
                        if recipient in CLIENTS:
                            print("Checking if receiver is client in the system...")
                            CLIENTS[recipient].send(f"From {username}: {message}".encode())
                            print(f"[DEBUG] Message sent from {username}.")
                            print(f"[DEBUG] Message sent is {message} ")
                            print(f"[DEBUG] Message delivered to {recipient}.")
                        else:
                            print(f"[DEBUG] Queuing message for offline user {recipient}.")
                            if recipient not in MESSAGE_QUEUES:
                                print(f"If recipient {recipient} is not in messages queue create it.")
                                MESSAGE_QUEUES[recipient] = queue.Queue()

                            MESSAGE_QUEUES[recipient].put(f"From {username}: {message} \n")
                            client.send(f"User {recipient} is not connected. Message stored.".encode())
                    else:
                        client.send(f"User '{recipient}' does not exist.".encode())
                        print(f"[DEBUG] Invalid recipient: {recipient}.")

                elif data_type == "RECEIVE":
                    print(f"[DEBUG] {username} is fetching their messages.")
                    username_lower = username.lower()

                    if username_lower in MESSAGE_QUEUES:
                        print(f"if {username} in the message queue as there is messages sent to it.")
                        while not MESSAGE_QUEUES[username_lower].empty():
                            print(f"User {username} have {MESSAGE_QUEUES[username_lower].qsize()} messages.")
                            print("Fetching Messages...")
                            queued_message = MESSAGE_QUEUES[username_lower].get()
                            client.send(queued_message.encode())
                            print(f"[DEBUG] Delivered queued message to {username}: {queued_message}")
                    client.send("END_OF_MESSAGES".encode())

                elif data_type == "EXIT":
                    print(f"[DEBUG] {username} disconnected.")
                    del CLIENTS[username]
                    client.close()
                    break
            except Exception as e:
                print(f"[DEBUG] Error while handling {username}: {e}")
                break
    except Exception as e:
        print(f"[DEBUG] Client handling error: {e}")
        client.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 5566))
    server.listen(5)
    print("[DEBUG] Server is running on port 5566.")
    while True:
        client, addr = server.accept()
        print(f"[DEBUG] New connection from {addr}.")
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == "__main__":
    start_server()
"""
"""from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
import socket
import threading
import queue

print("Server imports successful!")

USERS = {}
CLIENTS = {}
MESSAGE_QUEUES = {}

def generate_rsa_keys(username):
    print(f"[DEBUG] Generating RSA key pair for {username}...")
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    USERS[username] = {"private_key": private_key, "public_key": public_key}
    print(f"[DEBUG] Keys generated for {username} - Private: {private_key[:30]}..., Public: {public_key[:30]}...")
    return private_key, public_key

def challenge_response(client, username):
    print(f"[DEBUG] Starting challenge-response for {username}...")
    public_key = RSA.import_key(USERS[username]["public_key"])
    challenge = get_random_bytes(16)
    print(f"[DEBUG] Sending challenge to {username}.")
    client.send(challenge)
    response = client.recv(256)
    h = SHA256.new(challenge)
    try:
        pkcs1_15.new(public_key).verify(h, response)
        print(f"[DEBUG] Challenge-response successful for {username}.")
        return True
    except (ValueError, TypeError):
        print(f"[DEBUG] Challenge-response failed for {username}.")
        return False

def session_key_exchange(client, username):
    print(f"[DEBUG] Initiating session key exchange with {username}...")
    private_key = RSA.import_key(USERS[username]["private_key"])
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    encrypted_key = cipher_rsa.encrypt(session_key)
    print(f"[DEBUG] Sending encrypted session key to {username}.")
    client.send(encrypted_key)
    return session_key

def handle_client(client):
    try:
        username = client.recv(1024).decode().strip()
        print(f"[DEBUG] Handling client: {username}")

        if username.lower() not in [user.lower() for user in USERS]:
            print(f"[DEBUG] New user detected: {username}. Initiating registration process.")
            client.send("SIGN_UP".encode())
            private_key, public_key = generate_rsa_keys(username)
            USERS[username] = {"private_key": private_key, "public_key": public_key}
            MESSAGE_QUEUES[username.lower()] = queue.Queue()
            print(f"[DEBUG] User {username} registered successfully.")
        else:
            print(f"[DEBUG] Authenticating existing user: {username}")
            client.send("SIGN_IN".encode())
            if not challenge_response(client, username):
                print(f"[DEBUG] Authentication failed for {username}. Closing connection.")
                client.close()
                return

        CLIENTS[username] = client
        print(f"[DEBUG] {username} connected and authenticated.")

        while True:
            try:
                data_type = client.recv(1024).decode().strip()
                if data_type == "MESSAGE":
                    print(f"[DEBUG] Receiving message from {username}.")
                    data = client.recv(2048).decode()
                    try:
                        recipient, message = data.split("|", 1)
                    except ValueError:
                        print("[DEBUG] Invalid message format received.")
                        client.send("ERROR: Invalid data format.".encode())
                        continue

                    if recipient.lower() in [user.lower() for user in USERS]:
                        if recipient in CLIENTS:
                            CLIENTS[recipient].send(f"From {username}: {message}".encode())
                            print(f"[DEBUG] Message delivered to {recipient}.")
                        else:
                            if recipient not in MESSAGE_QUEUES:
                                MESSAGE_QUEUES[recipient] = queue.Queue()
                            MESSAGE_QUEUES[recipient].put(f"From {username}: {message}")
                            client.send(f"Message stored for {recipient}.".encode())
                    else:
                        client.send(f"User '{recipient}' does not exist.".encode())
                elif data_type == "RECEIVE":
                    print(f"[DEBUG] {username} is fetching their messages.")
                    while not MESSAGE_QUEUES.get(username, queue.Queue()).empty():
                        queued_message = MESSAGE_QUEUES[username].get()
                        client.send(queued_message.encode())
                    client.send("END_OF_MESSAGES".encode())
                elif data_type == "EXIT":
                    print(f"[DEBUG] {username} disconnected.")
                    del CLIENTS[username]
                    client.close()
                    break
            except Exception as e:
                print(f"[DEBUG] Error while handling {username}: {e}")
                break
    except Exception as e:
        print(f"[DEBUG] Client handling error: {e}")
        client.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 5566))
    server.listen(5)
    print("[DEBUG] Server is running on port 5566.")
    while True:
        client, addr = server.accept()
        print(f"[DEBUG] New connection from {addr}.")
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == "__main__":
    start_server()
"""
"""
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
import socket
import threading
import queue

print("Server imports successful!")

USERS = {}
CLIENTS = {}
MESSAGE_QUEUES = {}

def generate_rsa_keys(username):
    print(f"[DEBUG] Generating RSA key pair for {username}...")
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    USERS[username] = {"private_key": private_key, "public_key": public_key, "challenge": None}
    print(f"[DEBUG] Keys generated for {username} - Private: {private_key[:30]}..., Public: {public_key[:30]}...")
    return private_key, public_key

def generate_challenge(username):
    print(f"[DEBUG] Generating new challenge for {username}...")
    challenge = get_random_bytes(16)
    USERS[username]["challenge"] = challenge
    print(f"[DEBUG] Challenge for {username} stored.")
    return challenge

def challenge_response(client, username):
    print(f"[DEBUG] Starting challenge-response for {username}...")
    public_key = RSA.import_key(USERS[username]["public_key"])
    challenge = generate_challenge(username)
    print(f"[DEBUG] Sending challenge to {username}.")
    client.send(challenge)
    response = client.recv(256)
    h = SHA256.new(challenge)
    try:
        pkcs1_15.new(public_key).verify(h, response)
        print(f"[DEBUG] Challenge-response successful for {username}.")
        return True
    except (ValueError, TypeError):
        print(f"[DEBUG] Challenge-response failed for {username}.")
        return False

def session_key_exchange(client, username):
    print(f"[DEBUG] Initiating session key exchange with {username}...")
    private_key = RSA.import_key(USERS[username]["private_key"])
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    encrypted_key = cipher_rsa.encrypt(session_key)
    print(f"[DEBUG] Sending encrypted session key to {username}.")
    client.send(encrypted_key)
    return session_key

def handle_client(client):
    try:
        username = client.recv(1024).decode().strip()
        print(f"[DEBUG] Handling client: {username}")

        if username.lower() not in [user.lower() for user in USERS]:
            print(f"[DEBUG] New user detected: {username}. Initiating registration process.")
            client.send("SIGN_UP".encode())
            private_key, public_key = generate_rsa_keys(username)
            USERS[username] = {"private_key": private_key, "public_key": public_key, "challenge": None}
            MESSAGE_QUEUES[username.lower()] = queue.Queue()
            print(f"[DEBUG] User {username} registered successfully.")
        else:
            print(f"[DEBUG] Authenticating existing user: {username}")
            client.send("SIGN_IN".encode())
            if not challenge_response(client, username):
                print(f"[DEBUG] Authentication failed for {username}. Closing connection.")
                client.close()
                return

        CLIENTS[username] = client
        print(f"[DEBUG] {username} connected and authenticated.")

        while True:
            try:
                data_type = client.recv(1024).decode().strip()
                if data_type == "MESSAGE":
                    print(f"[DEBUG] Receiving message from {username}.")
                    data = client.recv(2048).decode()
                    try:
                        recipient, message = data.split("|", 1)
                    except ValueError:
                        print("[DEBUG] Invalid message format received.")
                        client.send("ERROR: Invalid data format.".encode())
                        continue

                    if recipient.lower() in [user.lower() for user in USERS]:
                        if recipient in CLIENTS:
                            CLIENTS[recipient].send(f"From {username}: {message}".encode())
                            print(f"[DEBUG] Message delivered to {recipient}.")
                        else:
                            MESSAGE_QUEUES[recipient.lower()].put(f"From {username}: {message}")
                            client.send(f"Message stored for {recipient}.".encode())
                            print(f"[DEBUG] Message queued for offline user {recipient}.")
                    else:
                        client.send(f"User '{recipient}' does not exist.".encode())
                        print(f"[DEBUG] User '{recipient}' does not exist. No queue created.")
                elif data_type == "RECEIVE":
                    print(f"[DEBUG] {username} is fetching their messages.")
                    if username.lower() in MESSAGE_QUEUES:
                        while not MESSAGE_QUEUES[username.lower()].empty():
                            queued_message = MESSAGE_QUEUES[username.lower()].get()
                            client.send(queued_message.encode())
                            print(f"[DEBUG] Delivered queued message to {username}: {queued_message}")
                    client.send("END_OF_MESSAGES".encode())
                elif data_type == "EXIT":
                    print(f"[DEBUG] {username} disconnected.")
                    del CLIENTS[username]
                    client.close()
                    break
            except Exception as e:
                print(f"[DEBUG] Error while handling {username}: {e}")
                break
    except Exception as e:
        print(f"[DEBUG] Client handling error: {e}")
        client.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 5566))
    server.listen(5)
    print("[DEBUG] Server is running on port 5566.")
    while True:
        client, addr = server.accept()
        print(f"[DEBUG] New connection from {addr}.")
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == "__main__":
    start_server()
"""

"""from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
import socket
import threading
import queue

print("Server imports successful!")

USERS = {}
CLIENTS = {}
MESSAGE_QUEUES = {}

def generate_rsa_keys(username):
    print(f"[DEBUG] Generating RSA key pair for {username}...")
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    USERS[username] = {"private_key": private_key, "public_key": public_key, "challenge": None}
    print(f"[DEBUG] Keys generated for {username} - Private: {private_key[:30]}..., Public: {public_key[:30]}...")
    return private_key, public_key

def generate_challenge(username):
    print(f"[DEBUG] Generating new challenge for {username}...")
    challenge = get_random_bytes(16)
    USERS[username]["challenge"] = challenge
    print(f"[DEBUG] Challenge for {username} stored: {challenge.hex()}.")
    return challenge

def validate_challenge(username, response):
    print(f"[DEBUG] Validating challenge response for {username}...")
    public_key = RSA.import_key(USERS[username]["public_key"])
    challenge = USERS[username]["challenge"]
    if challenge is None:
        print(f"[DEBUG] No challenge found for {username}. Validation failed.")
        return False

    h = SHA256.new(challenge)
    try:
        pkcs1_15.new(public_key).verify(h, response)
        print(f"[DEBUG] Challenge-response successful for {username}.")
        return True
    except (ValueError, TypeError):
        print(f"[DEBUG] Challenge-response failed for {username}.")
        return False

def session_key_exchange(client, username):
    print(f"[DEBUG] Initiating session key exchange with {username}...")
    private_key = RSA.import_key(USERS[username]["private_key"])
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    encrypted_key = cipher_rsa.encrypt(session_key)
    print(f"[DEBUG] Sending encrypted session key to {username}.")
    client.send(encrypted_key)
    return session_key

def handle_client(client):
    try:
        username = client.recv(1024).decode().strip()
        print(f"[DEBUG] Handling client: {username}")

        if username.lower() not in [user.lower() for user in USERS]:
            print(f"[DEBUG] New user detected: {username}. Initiating registration process.")
            client.send("SIGN_UP".encode())
            private_key, public_key = generate_rsa_keys(username)
            USERS[username] = {"private_key": private_key, "public_key": public_key, "challenge": None}
            MESSAGE_QUEUES[username.lower()] = queue.Queue()
            print(f"[DEBUG] User {username} registered successfully.")
        else:
            print(f"[DEBUG] Authenticating existing user: {username}")
            client.send("SIGN_IN".encode())
            challenge = generate_challenge(username)
            print(f"[DEBUG] Sending challenge to {username}.")
            client.send(challenge)
            response = client.recv(256)
            if not validate_challenge(username, response):
                print(f"[DEBUG] Authentication failed for {username}. Closing connection.")
                client.close()
                return

        CLIENTS[username] = client
        print(f"[DEBUG] {username} connected and authenticated.")

        while True:
            try:
                data_type = client.recv(1024).decode().strip()
                if data_type == "MESSAGE":
                    print(f"[DEBUG] Receiving message from {username}.")
                    data = client.recv(2048).decode()
                    try:
                        recipient, message = data.split("|", 1)
                    except ValueError:
                        print("[DEBUG] Invalid message format received.")
                        client.send("ERROR: Invalid data format.".encode())
                        continue

                    if recipient.lower() in [user.lower() for user in USERS]:
                        if recipient in CLIENTS:
                            CLIENTS[recipient].send(f"From {username}: {message}".encode())
                            print(f"[DEBUG] Message delivered to {recipient}.")
                        else:
                            MESSAGE_QUEUES[recipient.lower()].put(f"From {username}: {message}")
                            client.send(f"Message stored for {recipient}.".encode())
                            print(f"[DEBUG] Message queued for offline user {recipient}.")
                    else:
                        client.send(f"User '{recipient}' does not exist.".encode())
                        print(f"[DEBUG] User '{recipient}' does not exist. No queue created.")
                elif data_type == "RECEIVE":
                    print(f"[DEBUG] {username} is fetching their messages.")
                    if username.lower() in MESSAGE_QUEUES:
                        while not MESSAGE_QUEUES[username.lower()].empty():
                            queued_message = MESSAGE_QUEUES[username.lower()].get()
                            client.send(queued_message.encode())
                            print(f"[DEBUG] Delivered queued message to {username}: {queued_message}")
                    client.send("END_OF_MESSAGES".encode())
                elif data_type == "EXIT":
                    print(f"[DEBUG] {username} disconnected.")
                    del CLIENTS[username]
                    client.close()
                    break
            except Exception as e:
                print(f"[DEBUG] Error while handling {username}: {e}")
                break
    except Exception as e:
        print(f"[DEBUG] Client handling error: {e}")
        client.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 5566))
    server.listen(5)
    print("[DEBUG] Server is running on port 5566.")
    while True:
        client, addr = server.accept()
        print(f"[DEBUG] New connection from {addr}.")
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == "__main__":
    start_server()
"""

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
import socket
import threading
import queue

print("Server imports successful!")

USERS = {}
CLIENTS = {}
MESSAGE_QUEUES = {}

def generate_rsa_keys(username):
    print(f"[DEBUG] Generating RSA key pair for {username}...")
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    USERS[username] = {"private_key": private_key, "public_key": public_key, "challenge": None}
    print(f"[DEBUG] RSA keys generated for {username}.")
    return private_key, public_key

def generate_challenge(username):
    print(f"[DEBUG] Generating new challenge for {username}...")
    challenge = get_random_bytes(16)
    USERS[username]["challenge"] = challenge
    print(f"[DEBUG] Challenge generated and stored for {username}: {challenge.hex()}.")
    return challenge

def validate_challenge(username, response):
    print(f"[DEBUG] Validating challenge for {username}...")
    if USERS[username]["challenge"] is None:
        print(f"[DEBUG] No challenge stored for {username}.")
        return False

    public_key = RSA.import_key(USERS[username]["public_key"])
    h = SHA256.new(USERS[username]["challenge"])
    try:
        pkcs1_15.new(public_key).verify(h, response)
        print(f"[DEBUG] Challenge-response successful for {username}.")
        USERS[username]["challenge"] = None  # Clear the challenge after successful validation
        return True
    except (ValueError, TypeError):
        print(f"[DEBUG] Challenge-response failed for {username}.")
        return False

def session_key_exchange(client, username):
    print(f"[DEBUG] Initiating session key exchange for {username}...")
    private_key = RSA.import_key(USERS[username]["private_key"])
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    encrypted_key = cipher_rsa.encrypt(session_key)
    print(f"[DEBUG] Sending encrypted session key to {username}.")
    client.send(encrypted_key)
    return session_key

def handle_client(client):
    try:
        username = client.recv(1024).decode().strip()
        print(f"[DEBUG] Handling client: {username}")

        if username.lower() not in [user.lower() for user in USERS]:
            print(f"[DEBUG] New user detected: {username}. Initiating registration.")
            client.send("SIGN_UP".encode())
            private_key, public_key = generate_rsa_keys(username)
            USERS[username] = {"private_key": private_key, "public_key": public_key, "challenge": None}
            MESSAGE_QUEUES[username.lower()] = queue.Queue()
            print(f"[DEBUG] User {username} registered successfully.")
        else:
            print(f"[DEBUG] Authenticating existing user: {username}")
            client.send("SIGN_IN".encode())
            challenge = generate_challenge(username)
            client.send(challenge)
            response = client.recv(256)
            if not validate_challenge(username, response):
                print(f"[DEBUG] Authentication failed for {username}. Closing connection.")
                client.close()
                return

        CLIENTS[username] = client
        print(f"[DEBUG] {username} connected and authenticated.")

        while True:
            try:
                data_type = client.recv(1024).decode().strip()
                if data_type == "MESSAGE":
                    print(f"[DEBUG] Receiving message from {username}.")
                    data = client.recv(2048).decode()
                    try:
                        recipient, message = data.split("|", 1)
                    except ValueError:
                        print("[DEBUG] Invalid message format received.")
                        client.send("ERROR: Invalid data format.".encode())
                        continue

                    if recipient.lower() in [user.lower() for user in USERS]:
                        if recipient in CLIENTS:
                            CLIENTS[recipient].send(f"From {username}: {message}".encode())
                            print(f"[DEBUG] Message delivered to {recipient}.")
                        else:
                            MESSAGE_QUEUES[recipient.lower()].put(f"From {username}: {message}")
                            client.send(f"Message stored for {recipient}.".encode())
                            print(f"[DEBUG] Message queued for offline user {recipient}.")
                    else:
                        client.send(f"User '{recipient}' does not exist.".encode())
                        print(f"[DEBUG] User '{recipient}' does not exist. No queue created.")
                elif data_type == "RECEIVE":
                    print(f"[DEBUG] {username} is fetching their messages.")
                    if username.lower() in MESSAGE_QUEUES:
                        while not MESSAGE_QUEUES[username.lower()].empty():
                            queued_message = MESSAGE_QUEUES[username.lower()].get()
                            client.send(queued_message.encode())
                            print(f"[DEBUG] Delivered queued message to {username}: {queued_message}")
                    client.send("END_OF_MESSAGES".encode())
                elif data_type == "EXIT":
                    print(f"[DEBUG] {username} disconnected.")
                    del CLIENTS[username]
                    client.close()
                    break
            except Exception as e:
                print(f"[DEBUG] Error while handling {username}: {e}")
                break
    except Exception as e:
        print(f"[DEBUG] Client handling error: {e}")
        client.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 5566))
    server.listen(5)
    print("[DEBUG] Server is running on port 5566.")
    while True:
        client, addr = server.accept()
        print(f"[DEBUG] New connection from {addr}.")
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == "__main__":
    start_server()
