import socket
import os
import threading
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256

def receive_messages(client):
    """Continuously receive queued messages from the server."""
    print("[INFO] Receiving messages...")
    try:
        while True:
            message = client.recv(2048).decode(errors="ignore").strip()
            if message == "END_OF_MESSAGES":
                print("[INFO] End of message queue.")
                break  # Exit the loop when end signal is received
            elif "[INFO]" in message:  # Info messages from the server
                print(message)
            else:
                print(message)  # Regular queued messages
    except Exception as e:
        print(f"[ERROR] Error receiving messages: {e}")

def generate_and_save_keys(username):
    """Generate RSA keys and save them to .pem files."""
    if not os.path.exists(f"{username}_private.pem") or not os.path.exists(f"{username}_public.pem"):
        print(f"[DEBUG] Generating RSA keys for {username}.")
        private_key = RSA.generate(2048)
        with open(f"{username}_private.pem", "wb") as priv_file:
            priv_file.write(private_key.export_key())
        with open(f"{username}_public.pem", "wb") as pub_file:
            pub_file.write(private_key.publickey().export_key())
        print(f"[DEBUG] RSA keys generated and saved for {username}.")
    else:
        print(f"[DEBUG] RSA keys already exist for {username}.")

def sign_challenge(challenge, private_key):
    """Sign the server-provided challenge for authentication."""
    h = SHA256.new(challenge)
    print(f"[DEBUG] Signing challenge: {challenge.hex()}")
    return pkcs1_15.new(private_key).sign(h)

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Cipher import PKCS1_OAEP

def start_live_chat(client):
    """Handle live chat with AES encryption."""
    def receive_live_messages(session_key):
        """Receive messages during live chat."""
        try:
            while True:
                # Receive the encrypted message
                encrypted_message = client.recv(1024)
                if not encrypted_message:
                    break

                # Extract the IV (first 16 bytes) and ciphertext
                iv = encrypted_message[:16]
                ciphertext = encrypted_message[16:]

                # Decrypt the message
                cipher = AES.new(session_key, AES.MODE_CBC, iv=iv)
                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

                if plaintext.lower() == "exit":
                    print("[INFO] The other user has left the chat.")
                    break

                # Display the decrypted message
                print(plaintext)
        except Exception as e:
            print(f"[ERROR] Error receiving live messages: {e}")

    # Receive and decrypt the session key
    encrypted_session_key = client.recv(1024)
    with open(f"{username}_private.pem", "rb") as priv_file:
        private_key = RSA.import_key(priv_file.read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(encrypted_session_key)

    # Start a thread to handle incoming messages
    receiver_thread = threading.Thread(target=receive_live_messages, args=(session_key,), daemon=True)
    receiver_thread.start()

    # Handle outgoing messages
    try:
        while True:
            msg = input()
            if msg.lower() == "exit":
                cipher = AES.new(session_key, AES.MODE_CBC)
                iv = cipher.iv
                encrypted_message = iv + cipher.encrypt(pad("exit".encode(), AES.block_size))
                client.send(encrypted_message)
                print("[INFO] Exiting live conversation...")
                break

            # Encrypt the message with AES
            cipher = AES.new(session_key, AES.MODE_CBC)
            iv = cipher.iv
            encrypted_message = iv + cipher.encrypt(pad(msg.encode(), AES.block_size))
            client.send(encrypted_message)
    except Exception as e:
        print(f"[ERROR] Error sending live messages: {e}")
    finally:
        receiver_thread.join()  # Ensure the receiving thread finishes



def start_client(username):
    generate_and_save_keys(username)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client.connect(('localhost', 5566))
        client.send(username.encode())

        response = client.recv(1024).decode(errors="ignore")

        if response == "SIGN_UP":
            print(f"[DEBUG] {username} registered successfully.")
            with open(f"{username}_public.pem", "rb") as pub_file:
                public_key_pem = pub_file.read()
            client.send(public_key_pem)

        elif response == "SIGN_IN":
            with open(f"{username}_private.pem", "rb") as priv_file:
                private_key = RSA.import_key(priv_file.read())
            challenge = client.recv(1024)
            print(f"[DEBUG] Challenge received: {challenge.hex()}")
            signature = sign_challenge(challenge, private_key)
            client.send(signature)

            auth_response = client.recv(1024).decode(errors="ignore")
            if auth_response == "AUTH_FAILED":
                print("[ERROR] Authentication failed.")
                return
            print(f"[DEBUG] {username} authenticated successfully.")

        while True:
            choice = input("Choose an option: (1) Send Message, (2) Receive Messages, (3) Live Conversation, (q) Quit: ")
            if choice == '1':
                recipient = input("Enter recipient username: ").strip()
                message = input("Enter message: ").strip()
                client.send("MESSAGE".encode())
                client.send(f"{recipient}|{message}".encode())
                print(f"[DEBUG] Message sent to {recipient}.")
            elif choice == '2':
                client.send("RECEIVE".encode())
                receive_messages(client)
                print("[INFO] Returning to main menu...")  # Notify user that the menu is shown again
            elif choice == '3':
                target_user = input("Enter the username of the user you want to talk to: ").strip()
                client.send("LIVE".encode())  # Inform server about live chat request
                client.send(target_user.encode())  # Send target user's username to server

                while True:
                    try:
                        response = client.recv(1024).decode(errors="ignore")

                        if response == "LIVE_REQUEST_SENT":
                            print(f"[INFO] Live chat request sent to {target_user}. Waiting for response...")

                        elif response.startswith("LIVE_REQUEST"):
                            sender = response.split("|", 1)[1]
                            print(f"[INFO] Live chat request received from {sender}.")
                            accept = input("Do you want to accept the live chat request? (yes/no): ").strip().lower()
                            if accept == "yes":
                                client.send("LIVE_ACCEPT".encode())
                                print("[INFO] Waiting for live chat to start...")
                            else:
                                client.send("LIVE_DECLINE".encode())
                                print("[INFO] Live chat request declined.")
                                break

                        elif response == "LIVE_READY":
                            print(f"[INFO] Live chat started with {target_user}. Type 'exit' to leave.")
                            start_live_chat(client)  # Start the live chat session
                            break

                        elif response == "LIVE_DECLINED":
                            print(f"[INFO] {target_user} declined the live chat request.")
                            break



                        elif response == "USER_OFFLINE":
                            print(f"[INFO] {target_user} is offline or not available.")
                            break

                        elif response == "LIVE_ERROR":
                            print("[ERROR] Failed to start live chat. Please try again.")
                            break

                        else:
                            print("[ERROR] Unexpected response received.")
                            break

                    except Exception as e:
                        print(f"[ERROR] An error occurred during live chat setup: {e}")
                        break

            elif choice == 'q':
                client.send("EXIT".encode())
                break
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
    finally:
        client.close()
        print("[DEBUG] Client socket closed.")

if __name__ == "__main__":
    username = input("Enter your username: ")
    start_client(username)
