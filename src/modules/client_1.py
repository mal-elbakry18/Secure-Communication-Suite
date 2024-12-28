"""from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
import socket
import os
import threading


def receive_messages(client):
    #Continuously receive messages from the server.
    while True:
        try:
            message = client.recv(2048).decode(errors="ignore")
            if message == "END_OF_MESSAGES":
                print("[INFO] No more messages to display.")
                break
            elif message:
                print(f"\n{message}")  # Print the received message
            else:
                print("[INFO] No messages received.")
                break
        except Exception as e:
            print(f"[ERROR] Error receiving messages: {e}")
            break


def generate_and_save_keys(username):
    #Generate RSA keys and save them to .pem files.
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
    h = SHA256.new(challenge)
    print(f"[DEBUG] Signing challenge: {challenge.hex()}")
    return pkcs1_15.new(private_key).sign(h)


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
            elif choice == '3':
                target_user = input("Enter the username of the user you want to talk to: ").strip()
                client.send("LIVE".encode())
                client.send(target_user.encode())
                response = client.recv(1024).decode()

                if response.startswith("LIVE_REQUEST"):
                    sender = response.split("|")[1]
                    print(f"[INFO] Live chat request received from {sender}.")
                    accept = input("Do you want to accept the live chat request? (yes/no): ").strip().lower()
                    if accept == "yes":
                        client.send("LIVE_ACCEPT".encode())
                        print("[INFO] Waiting for live chat to start...")
                    else:
                        client.send("LIVE_DECLINE".encode())

                elif response == "LIVE_READY":
                    print(f"[INFO] Live chat started with {target_user}. Type 'exit' to leave.")

                    # Start a thread to handle incoming messages
                    threading.Thread(target=receive_messages, args=(client,), daemon=True).start()

                    # Handle outgoing messages
                    while True:
                        msg = input()
                        if msg.lower() == "exit":
                            client.send(msg.encode())
                            break
                        client.send(msg.encode())
                elif response == "LIVE_DECLINED":
                    print(f"[INFO] {target_user} declined the live chat request.")
                elif response == "USER_OFFLINE":
                    print(f"[INFO] {target_user} is offline or not available.")

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
    start_client(username)"""

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
import socket
import os
import threading


def receive_messages(client):
    """Continuously receive queued messages from the server."""
    while True:
        try:
            message = client.recv(2048).decode(errors="ignore")
            if message == "END_OF_MESSAGES":
                print("[INFO] No more messages to display.")
                break  # Break out of the loop to return to the main menu
            elif message:
                print(f"\n{message}")  # Print the received message
            else:
                break
        except Exception as e:
            print(f"[ERROR] Error receiving messages: {e}")
            break

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


def start_live_chat(client):
    """Handle live chat with proper exit handling."""
    def receive_live_messages():
        """Receive messages in a live chat."""
        while True:
            try:
                message = client.recv(1024).decode(errors="ignore")
                if not message or message.lower() == "exit":
                    print("[INFO] Live conversation ended.")
                    break
                print(message)
            except Exception as e:
                print(f"[ERROR] Error receiving live messages: {e}")
                break

    # Start a thread to receive messages
    receiver_thread = threading.Thread(target=receive_live_messages, daemon=True)
    receiver_thread.start()

    # Handle sending messages
    while True:
        try:
            msg = input()
            if msg.lower() == "exit":
                client.send(msg.encode())
                print("[INFO] Exiting live conversation...")
                break
            client.send(msg.encode())
        except Exception as e:
            print(f"[ERROR] Error sending live messages: {e}")
            break

    receiver_thread.join()  # Ensure receiving thread finishes before exiting



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

                client.send("LIVE".encode())

                client.send(target_user.encode())

                while True:

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

                            break


                    elif response == "LIVE_READY":

                        print(f"[INFO] Live chat started with {target_user}. Type 'exit' to leave.")

                        start_live_chat(client)

                        break


                    elif response == "LIVE_DECLINED":

                        print(f"[INFO] {target_user} declined the live chat request.")

                        break


                    elif response == "USER_OFFLINE":

                        print(f"[INFO] {target_user} is offline or not available.")

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
