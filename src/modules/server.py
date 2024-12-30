
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
import socket
import threading
import queue
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
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
    """Handle bidirectional live chat between two users with AES encryption."""
    try:
        client1 = CLIENTS[user1]
        client2 = CLIENTS[user2]

        # Notify both users that the live chat has started
        client1.send(f"[INFO] Live chat started with {user2}. Type 'exit' to leave.".encode())
        client2.send(f"[INFO] Live chat started with {user1}. Type 'exit' to leave.".encode())

        # Generate a shared session key
        session_key = generate_session_key()

        # Encrypt session key for each user using their RSA public key and send it
        cipher_rsa1 = PKCS1_OAEP.new(RSA.import_key(USERS[user1]["public_key"]))
        cipher_rsa2 = PKCS1_OAEP.new(RSA.import_key(USERS[user2]["public_key"]))
        client1.send(cipher_rsa1.encrypt(session_key))
        client2.send(cipher_rsa2.encrypt(session_key))

        # Define message relaying functions
        def relay_messages(sender, receiver, sender_name, session_key):
            """Relay messages from one client to another using AES encryption."""
            try:
                while True:
                    # Receive the encrypted message from the sender
                    encrypted_message = sender.recv(1024)
                    if not encrypted_message:
                        break

                    # Extract the IV (first 16 bytes) and ciphertext
                    iv = encrypted_message[:16]
                    ciphertext = encrypted_message[16:]

                    # Decrypt the message using AES
                    cipher = AES.new(session_key, AES.MODE_CBC, iv=iv)
                    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

                    # Handle "exit" message
                    if plaintext.lower() == "exit":
                        receiver.send(f"[INFO] {sender_name} has left the live chat.".encode())
                        break

                    # Encrypt the message for the receiver
                    cipher = AES.new(session_key, AES.MODE_CBC)
                    iv = cipher.iv
                    encrypted_response = iv + cipher.encrypt(
                        pad(f"{sender_name}: {plaintext}".encode(), AES.block_size))

                    # Send the encrypted message to the receiver
                    receiver.send(encrypted_response)
            except Exception as e:
                print(f"[ERROR] Error relaying messages from {sender_name}: {e}")
                receiver.send(f"[ERROR] Connection lost with {sender_name}.".encode())

        # Start threads for bidirectional communication
        thread1 = threading.Thread(target=relay_messages, args=(client1, client2, user1, session_key), daemon=True)
        thread2 = threading.Thread(target=relay_messages, args=(client2, client1, user2, session_key), daemon=True)
        thread1.start()
        thread2.start()

        # Wait for both threads to finish before ending the live chat
        thread1.join()
        thread2.join()
    except Exception as e:
        print(f"[ERROR] Live chat handling error between {user1} and {user2}: {e}")
    finally:
        # Notify both users that the chat has ended (if still connected)
        if user1 in CLIENTS:
            CLIENTS[user1].send("[INFO] Live chat ended.".encode())
        if user2 in CLIENTS:
            CLIENTS[user2].send("[INFO] Live chat ended.".encode())


def handle_client(client):
    try:
        # Step 1: Receive username and authenticate/register
        username = client.recv(1024).decode().strip()
        print(f"[DEBUG] Handling client: {username}")

        if username not in USERS:
            client.send("SIGN_UP".encode())
            public_key_pem = client.recv(2048).decode(errors="ignore")
            try:
                USERS[username] = {"public_key": public_key_pem, "challenge": None}
                MESSAGE_QUEUES[username] = queue.Queue()
                CLIENTS[username] = client
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
            if validate_challenge(username, signed_challenge):
                client.send("AUTH_SUCCESS".encode())
                CLIENTS[username] = client
                print(f"[DEBUG] {username} authenticated successfully.")
            else:
                client.send("AUTH_FAILED".encode())
                client.close()
                return

        # Step 2: Handle client requests
        while True:
            try:
                data_type = client.recv(1024).decode(errors="ignore").strip()
                if not data_type:
                    raise ConnectionResetError("Client disconnected.")

                if data_type == "MESSAGE":
                    recipient, message = client.recv(2048).decode(errors="ignore").split("|", 1)
                    if recipient in USERS:
                        if recipient in CLIENTS:
                            CLIENTS[recipient].send(f"From {username}: {message}".encode())
                        else:
                            MESSAGE_QUEUES[recipient].put(f"From {username}: {message}")
                            client.send("Message queued.".encode())
                    else:
                        client.send("ERROR: Recipient not found.".encode())

                elif data_type == "RECEIVE":
                    if username in MESSAGE_QUEUES:
                        while not MESSAGE_QUEUES[username].empty():
                            queued_message = MESSAGE_QUEUES[username].get()
                            client.send(queued_message.encode())
                    client.send("END_OF_MESSAGES".encode())


                elif data_type == "LIVE":

                    try:

                        target_user = client.recv(1024).decode().strip()

                        print(f"[DEBUG] {username} is requesting a live conversation with {target_user}.")

                        if target_user in CLIENTS:

                            try:

                                # Notify the initiating user that the request has been sent

                                client.send("LIVE_REQUEST_SENT".encode())

                                CLIENTS[target_user].send(f"LIVE_REQUEST|{username}".encode())

                                print(f"[DEBUG] Live chat request sent to {target_user} from {username}.")

                                # Wait for the target user's response

                                response = CLIENTS[target_user].recv(1024).decode().strip()

                                if response == "LIVE_ACCEPT":

                                    print(f"[DEBUG] {target_user} accepted the live chat request from {username}.")

                                    client.send("LIVE_READY".encode())

                                    CLIENTS[target_user].send("LIVE_READY".encode())

                                    handle_live_chat(username, target_user)


                                elif response == "LIVE_DECLINE":

                                    print(f"[DEBUG] {target_user} declined the live chat request from {username}.")

                                    client.send("LIVE_DECLINED".encode())

                                else:

                                    print(f"[ERROR] Invalid response from {target_user}: {response}")

                                    client.send("LIVE_ERROR".encode())

                            except BrokenPipeError:

                                print(f"[ERROR] Target user {target_user} disconnected during live chat setup.")

                                client.send("USER_OFFLINE".encode())

                        else:

                            print(f"[DEBUG] {target_user} is not online.")

                            client.send("USER_OFFLINE".encode())

                    except Exception as e:

                        print(f"[ERROR] Error during live chat setup for {username}: {e}")

                        client.send("LIVE_ERROR".encode())


                elif data_type == "EXIT":
                    print(f"[DEBUG] {username} disconnected.")
                    del CLIENTS[username]
                    client.close()
                    break

            except (ConnectionResetError, BrokenPipeError):
                print(f"[DEBUG] Client {username} disconnected abruptly.")
                if username in CLIENTS:
                    del CLIENTS[username]
                break
            except Exception as e:
                print(f"[ERROR] Error handling {username}: {e}")
                break
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        if username in CLIENTS:
            del CLIENTS[username]
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
            start_server()

''' elif data_type == "LIVE":

                   try:

                       target_user = client.recv(1024).decode().strip()

                       print(f"[DEBUG] {username} is requesting a live conversation with {target_user}.")

                       if target_user in CLIENTS:

                           CLIENTS[target_user].send(f"LIVE_REQUEST|{username}".encode())

                           print(f"[DEBUG] Live chat request sent to {target_user} from {username}.")

                           # Wait for the target user's response

                           response = CLIENTS[target_user].recv(1024).decode()

                           if response == "LIVE_ACCEPT":

                               print(f"[DEBUG] {target_user} accepted the live chat request from {username}.")

                               client.send("LIVE_READY".encode())

                               CLIENTS[target_user].send("LIVE_READY".encode())

                               handle_live_chat(username, target_user)

                           elif response == "LIVE_DECLINE":

                               print(f"[DEBUG] {target_user} declined the live chat request from {username}.")

                               client.send("LIVE_DECLINED".encode())

                       else:

                           print(f"[DEBUG] {target_user} is not online.")

                           client.send("USER_OFFLINE".encode())

                   except Exception as e:

                       print(f"[ERROR] Error during live chat setup for {username}: {e}")

                       client.send("LIVE_ERROR".encode())'''