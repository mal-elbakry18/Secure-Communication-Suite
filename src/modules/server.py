
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
    """Handles synchronized live chat between two users."""
    try:
        client1 = CLIENTS[user1]
        client2 = CLIENTS[user2]

        # Notify both users that the live chat has started
        client1.send(f"[INFO] Live chat started with {user2}. Type 'exit' to leave.".encode())
        client2.send(f"[INFO] Live chat started with {user1}. Type 'exit' to leave.".encode())

        def relay_messages(sender, receiver, sender_name):
            """Relay messages from one client to another."""
            while True:
                try:
                    message = sender.recv(1024).decode()
                    if message.lower() == "exit":
                        receiver.send(f"[INFO] {sender_name} has left the live chat.".encode())
                        break
                    receiver.send(f"[LIVE] {sender_name}: {message}".encode())
                except Exception as e:
                    print(f"[ERROR] Live chat relay error: {e}")
                    break

        # Start threads for both directions
        thread1 = threading.Thread(target=relay_messages, args=(client1, client2, user1), daemon=True)
        thread2 = threading.Thread(target=relay_messages, args=(client2, client1, user2), daemon=True)
        thread1.start()
        thread2.start()

        # Wait for both threads to finish before ending live chat
        thread1.join()
        thread2.join()
    except Exception as e:
        print(f"[ERROR] Live chat synchronization failed: {e}")



def handle_client(client):
    try:
        # Step 1: Receive username and authenticate/register
        username = client.recv(1024).decode().strip()
        print(f"[DEBUG] Handling client: {username}")

        if username not in USERS:
            # New user registration
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
            # Existing user authentication
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
                CLIENTS[username] = client
                print(f"[DEBUG] {username} authenticated successfully.")
            except (ValueError, TypeError):
                client.send("AUTH_FAILED".encode())
                print(f"[DEBUG] Authentication failed for {username}.")
                client.close()
                return

        # Step 2: Handle client requests
        while True:
            try:
                data_type = client.recv(1024).decode(errors="ignore").strip()

                if data_type == "MESSAGE":
                    recipient, message = client.recv(2048).decode(errors="ignore").split("|", 1)
                    if recipient in USERS:
                        if recipient in CLIENTS:
                            CLIENTS[recipient].send(f"From {username}: {message}".encode())
                            print(f"From {username}: {message}")
                            print(f"[DEBUG] Message delivered to {recipient}.")
                        else:
                            MESSAGE_QUEUES[recipient].put(f"From {username}: {message}")
                            print(f"From offline {username}: {message}")
                            print(f"[DEBUG] Message queued for offline user {recipient}.")
                            client.send("Message queued.".encode())
                    else:
                        client.send("ERROR: Recipient not found.".encode())
                        print(f"[DEBUG] Recipient {recipient} does not exist.")

                elif data_type == "RECEIVE":
                    print(f"[DEBUG] {username} is fetching their messages.")
                    while not MESSAGE_QUEUES[username].empty():
                        queued_message = MESSAGE_QUEUES[username].get()
                        print(f"[DEBUG] {username} received message: {queued_message}")
                        client.send(queued_message.encode())
                        print(f"[DEBUG] Delivered queued message to {username}: {queued_message}")
                    client.send("END_OF_MESSAGES".encode())
                    print(f"[DEBUG] End of messages signal sent to {username}.")


                elif data_type == "LIVE":

                    target_user = client.recv(1024).decode().strip()

                    print(f"[DEBUG] {username} is requesting a live conversation with {target_user}.")

                    if target_user in CLIENTS:

                        try:

                            # Notify the target user about the live chat request

                            CLIENTS[target_user].send(f"LIVE_REQUEST|{username}".encode())

                            # Wait for the target user's response

                            response = CLIENTS[target_user].recv(1024).decode()

                            if response == "LIVE_ACCEPT":

                                # Notify both users that the chat is ready

                                client.send("LIVE_READY".encode())

                                CLIENTS[target_user].send("LIVE_READY".encode())

                                print(f"[DEBUG] Live chat started between {username} and {target_user}.")

                                # Start the live chat session

                                handle_live_chat(username, target_user)

                            elif response == "LIVE_DECLINE":

                                client.send("LIVE_DECLINED".encode())

                                print(f"[DEBUG] {target_user} declined the live chat request from {username}.")

                        except Exception as e:

                            print(f"[ERROR] Error during live chat setup: {e}")

                            client.send("USER_OFFLINE".encode())

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


