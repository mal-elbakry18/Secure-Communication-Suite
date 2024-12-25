
"""def session_key_exchange(client, username):
    print(f"[DEBUG] Initiating session key exchange for {username}...")
    private_key = RSA.import_key(USERS[username]["private_key"])
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    encrypted_key = cipher_rsa.encrypt(session_key)
    print(f"[DEBUG] Sending encrypted session key to {username}.")
    client.send(encrypted_key)
    return session_key"""

"""def generate_rsa_keys(username):
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
    return challenge"""

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


def validate_challenge(username, response):
    #Validate the challenge-response for a user.
    print(f"[DEBUG] Validating challenge for {username}.")
    challenge = USERS[username]["challenge"]
    if challenge is None:
        print("[ERROR] No challenge found for user.")
        return False
    public_key = RSA.import_key(USERS[username]["public_key"])
    h = SHA256.new(challenge)
    try:
        pkcs1_15.new(public_key).verify(h, response)
        USERS[username]["challenge"] = None  # Clear challenge
        return True
    except (ValueError, TypeError):
        return False

def handle_client(client):
    try:
        username = client.recv(1024).decode().strip()
        print(f"[DEBUG] Handling client: {username}")

        if username not in USERS:
            client.send("SIGN_UP".encode())
            public_key_pem = client.recv(2048)  # Receive public key as bytes
            try:
                public_key = RSA.import_key(public_key_pem)  # Import the public key
                USERS[username] = {"public_key": public_key, "challenge": None}
                MESSAGE_QUEUES[username] = queue.Queue()
                print(f"[DEBUG] {username} registered successfully.")
            except ValueError:
                print(f"[ERROR] Invalid RSA key format for {username}.")
                client.send("ERROR: Invalid RSA key format.".encode())
                client.close()
                return
        else:
            client.send("SIGN_IN".encode())
            USERS[username]["challenge"] = get_random_bytes(16)
            client.send(USERS[username]["challenge"])
            response = client.recv(1024)  # Receive the signed challenge
            if not validate_challenge(username, response):
                client.send("AUTH_FAILED".encode())
                print(f"[DEBUG] Authentication failed for {username}.")
                client.close()
                return
            client.send("AUTH_SUCCESS".encode())
            print(f"[DEBUG] {username} authenticated successfully.")

        CLIENTS[username] = client
        while True:
            try:
                data_type = client.recv(1024).decode(errors="ignore").strip()
                if data_type == "MESSAGE":
                    recipient, message = client.recv(2048).decode(errors="ignore").split("|", 1)
                    if recipient in USERS:
                        if recipient in CLIENTS:
                            CLIENTS[recipient].send(f"From {username}: {message}".encode())
                            print(f"[DEBUG] Message delivered to {recipient}.")
                        else:
                            MESSAGE_QUEUES[recipient].put(f"From {username}: {message}")
                            client.send(f"Message queued for offline user {recipient}.".encode())
                            print(f"[DEBUG] Message queued for offline user {recipient}.")
                    else:
                        client.send(f"ERROR: Recipient {recipient} not found.".encode())
                        print(f"[DEBUG] Recipient {recipient} does not exist.")
                elif data_type == "RECEIVE":
                    print(f"[DEBUG] {username} is fetching their messages.")
                    if username.lower() in MESSAGE_QUEUES:
                        while not MESSAGE_QUEUES[username.lower()].empty():
                                queued_message = MESSAGE_QUEUES[username.lower()].get()
                                client.send(queued_message.encode())
                                print(f"[DEBUG] Delivered queued message to {username}: {queued_message}")
                    client.send("END_OF_MESSAGES".encode())  # Signal end of messages

                elif data_type == "EXIT":
                    print(f"[DEBUG] {username} disconnected.")
                    del CLIENTS[username]
                    client.close()
                    break
            except Exception as e:
                print(f"[ERROR] Error handling {username}: {e}")
                break
    except Exception as e:
                print(f"[ERROR] Unexpected error: {e}")
                client.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 5566))
    server.listen(5)
    print("[DEBUG] Server is running.")
    while True:
        client, _ = server.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()

if __name__ == "__main__":
   start_server()"""


from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
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


def validate_challenge(username, response):
    """Validate the challenge-response for a user."""
    print(f"[DEBUG] Validating challenge for {username}.")
    challenge = USERS[username]["challenge"]
    if challenge is None:
        print("[ERROR] No challenge found for user.")
        return False
    public_key = RSA.import_key(USERS[username]["public_key"])
    h = SHA256.new(challenge)
    try:
        pkcs1_15.new(public_key).verify(h, response)
        USERS[username]["challenge"] = None  # Clear challenge
        print(f"[DEBUG] Challenge successfully validated for {username}.")
        return True
    except (ValueError, TypeError):
        print(f"[ERROR] Challenge validation failed for {username}.")
        return False

def generate_session_key():
    """Generate a random AES session key."""
    session_key = get_random_bytes(16)
    print(f"[DEBUG] Generated session key: {session_key.hex()}")
    return session_key


def handle_live_chat(user1, user2):
    """Handles live chat between two users."""
    try:
        client1 = CLIENTS[user1]
        client2 = CLIENTS[user2]

        def relay_messages(sender, receiver, sender_name, receiver_name):
            """Relays messages between two clients."""
            while True:
                try:
                    message = sender.recv(1024).decode()
                    if message.lower() == "exit":
                        receiver.send(f"[INFO] {sender_name} has left the live conversation.".encode())
                        sender.send("[INFO] You have left the live conversation.".encode())
                        break
                    receiver.send(f"[LIVE] {sender_name}: {message}".encode())
                except Exception as e:
                    print(f"[ERROR] Live chat error: {e}")
                    break

        threading.Thread(target=relay_messages, args=(client1, client2, user1, user2), daemon=True).start()
        threading.Thread(target=relay_messages, args=(client2, client1, user2, user1), daemon=True).start()

    except Exception as e:
        print(f"[ERROR] Live chat failed: {e}")

def handle_client(client, username):
    """Handles communication with a client."""
    while True:
        try:
            data_type = client.recv(1024).decode(errors="ignore").strip()
            if data_type == "MESSAGE":
                recipient, message = client.recv(2048).decode(errors="ignore").split("|", 1)
                if recipient in USERS:
                    if recipient in CLIENTS:
                        CLIENTS[recipient].send(f"From {username}: {message}".encode())
                        print(f"[DEBUG] Message delivered to {recipient}.")
                    else:
                        MESSAGE_QUEUES[recipient].put(f"From {username}: {message}")
                        print(f"[DEBUG] Message queued for offline user {recipient}.")
                        client.send("Message queued.".encode())
                else:
                    client.send("ERROR: Recipient not found.".encode())
                    print(f"[DEBUG] Recipient {recipient} does not exist.")
            elif data_type == "RECEIVE":
                print(f"[DEBUG] {username} is fetching their messages.")
                if username in MESSAGE_QUEUES:
                    while not MESSAGE_QUEUES[username].empty():
                        queued_message = MESSAGE_QUEUES[username].get()
                        client.send(queued_message.encode())
                        print(f"[DEBUG] Delivered queued message to {username}: {queued_message}")
                client.send("END_OF_MESSAGES".encode())
                print(f"[DEBUG] End of messages signal sent to {username}.")
            elif data_type == "LIVE":
                target_user = client.recv(1024).decode(errors="ignore").strip()
                print(f"[DEBUG] {username} is requesting a live conversation with {target_user}.")
                if target_user in CLIENTS:
                    client.send("LIVE_READY".encode())
                    CLIENTS[target_user].send(f"LIVE_REQUEST|{username}".encode())
                    handle_live_chat(username, target_user)
                else:
                    client.send("USER_OFFLINE".encode())
                    print(f"[DEBUG] {target_user} is not online.")
            elif data_type == "EXIT":
                print(f"[DEBUG] {username} disconnected.")
                del CLIENTS[username]
                client.close()
                break
        except Exception as e:
            print(f"[ERROR] Error handling {username}: {e}")
            break


def main_handle_client(client):
    """Handles the initial connection and authentication of a client."""
    try:
        username = client.recv(1024).decode(errors="ignore").strip()
        print(f"[DEBUG] Handling client: {username}")

        if username not in USERS:
            client.send("SIGN_UP".encode())
            public_key_pem = client.recv(2048).decode(errors="ignore")
            try:
                USERS[username] = {"public_key": public_key_pem, "challenge": None}
                MESSAGE_QUEUES[username] = queue.Queue()
                print(f"[DEBUG] {username} registered successfully.")
            except Exception as e:
                print(f"[ERROR] Error registering user {username}: {e}")
                client.close()
                return
        else:
            client.send("SIGN_IN".encode())
            USERS[username]["challenge"] = get_random_bytes(16)
            client.send(USERS[username]["challenge"])
            signed_challenge = client.recv(2048)
            public_key = RSA.import_key(USERS[username]["public_key"])
            h = SHA256.new(USERS[username]["challenge"])
            try:
                pkcs1_15.new(public_key).verify(h, signed_challenge)
                USERS[username]["challenge"] = None
                client.send("AUTH_SUCCESS".encode())
                print(f"[DEBUG] {username} authenticated successfully.")
            except (ValueError, TypeError):
                client.send("AUTH_FAILED".encode())
                print(f"[DEBUG] Authentication failed for {username}.")
                client.close()
                return

        CLIENTS[username] = client
        handle_client(client, username)

    except Exception as e:
        print(f"[ERROR] Unexpected error during initial handling: {e}")
        client.close()



 #Commented code for the last working code of all functionalities except the live
"""
def handle_client(client):
    try:
        username = client.recv(1024).decode().strip()
        print(f"[DEBUG] Handling client: {username}")

        if username not in USERS:
            client.send("SIGN_UP".encode())
            public_key_pem = client.recv(2048).decode(errors="ignore")
            try:
                USERS[username] = {"public_key": public_key_pem, "challenge": None}
                MESSAGE_QUEUES[username] = queue.Queue()
                print(f"[DEBUG] {username} registered successfully.")
            except Exception as e:
                print(f"[ERROR] Error registering user {username}: {e}")
                client.close()
                return
        else:
            client.send("SIGN_IN".encode())
            USERS[username]["challenge"] = get_random_bytes(16)
            client.send(USERS[username]["challenge"])
            signed_challenge = client.recv(2048)
            public_key = RSA.import_key(USERS[username]["public_key"])
            h = SHA256.new(USERS[username]["challenge"])
            try:
                pkcs1_15.new(public_key).verify(h, signed_challenge)
                USERS[username]["challenge"] = None
                client.send("AUTH_SUCCESS".encode())
                print(f"[DEBUG] {username} authenticated successfully.")
            except (ValueError, TypeError):
                client.send("AUTH_FAILED".encode())
                print(f"[DEBUG] Authentication failed for {username}.")
                client.close()
                return

        CLIENTS[username] = client

        while True:
            try:
                data_type = client.recv(1024).decode(errors="ignore").strip()
                if data_type == "MESSAGE":
                    recipient, message = client.recv(2048).decode(errors="ignore").split("|", 1)
                    if recipient in USERS:
                        if recipient in CLIENTS:
                            CLIENTS[recipient].send(f"From {username}: {message}".encode())
                            print(f"[DEBUG] Message delivered to {recipient}.")
                        else:
                            MESSAGE_QUEUES[recipient].put(f"From {username}: {message}")
                            print(f"[DEBUG] Message queued for offline user {recipient}.")
                            client.send("Message queued.".encode())
                    else:
                        client.send("ERROR: Recipient not found.".encode())
                        print(f"[DEBUG] Recipient {recipient} does not exist.")
                elif data_type == "RECEIVE":
                    print(f"[DEBUG] {username} is fetching their messages.")
                    if username in MESSAGE_QUEUES:
                        while not MESSAGE_QUEUES[username].empty():
                            queued_message = MESSAGE_QUEUES[username].get()
                            client.send(queued_message.encode())
                            print(f"[DEBUG] Delivered queued message to {username}: {queued_message}")
                    client.send("END_OF_MESSAGES".encode())  # Signal end of messages
                    print(f"[DEBUG] End of messages signal sent to {username}.")
                elif data_type == "LIVE":
                    target_user = client.recv(1024).decode().strip()
                    print(f"[DEBUG] {username} is requesting a live conversation with {target_user}.")
                    if target_user in CLIENTS:
                        client.send("LIVE_READY".encode())
                        CLIENTS[target_user].send(f"LIVE_REQUEST|{username}".encode())
                        print(f"[DEBUG] Live conversation initiated between {username} and {target_user}.")

                        # Start bi-directional live chat
                        def live_chat(sender, receiver):
                            while True:
                                try:
                                    msg = sender.recv(1024).decode(errors="ignore")
                                    if msg.lower() == "exit":
                                        sender.send("END_LIVE".encode())
                                        receiver.send("END_LIVE".encode())
                                        print(f"[DEBUG] Live conversation ended between {username} and {target_user}.")
                                        break
                                    receiver.send(f"[LIVE] {username}: {msg}".encode())
                                except Exception as e:
                                    print(f"[ERROR] Live chat error: {e}")
                                    break

                        # Start threads for bi-directional communication
                        threading.Thread(target=live_chat, args=(client, CLIENTS[target_user])).start()
                        threading.Thread(target=live_chat, args=(CLIENTS[target_user], client)).start()
                    else:
                        client.send("USER_OFFLINE".encode())
                        print(f"[DEBUG] {target_user} is not online.")
                elif data_type == "EXIT":
                    print(f"[DEBUG] {username} disconnected.")
                    del CLIENTS[username]
                    client.close()
                    break
            except Exception as e:
                print(f"[ERROR] Error handling {username}: {e}")
                break
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        client.close()

"""

"""
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 5566))
    server.listen(5)
    print("[DEBUG] Server is running.")
    while True:
        client, _ = server.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()
"""

def start_server():
    """Starts the server and listens for incoming connections."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 5566))
    server.listen(5)
    print("[INFO] Server is running on port 5566.")

    while True:
        client, addr = server.accept()
        print(f"[INFO] New connection from {addr}.")
        threading.Thread(target=main_handle_client, args=(client,), daemon=True).start()


if __name__ == "__main__":
    start_server()
